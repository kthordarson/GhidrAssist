package ghidrassist.graphrag.extraction;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.decompiler.DecompiledFunction;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.block.CodeBlock;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;

import ghidrassist.graphrag.BinaryKnowledgeGraph;
import ghidrassist.graphrag.nodes.EdgeType;
import ghidrassist.graphrag.nodes.KnowledgeNode;
import ghidrassist.graphrag.nodes.NodeType;

import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Extracts structural information from Ghidra binaries and populates the knowledge graph.
 *
 * This extractor handles:
 * - Function enumeration and decompilation caching
 * - Call graph extraction (CALLS edges)
 * - Basic block extraction (optional, for BLOCK nodes)
 * - Cross-reference extraction (REFERENCES edges)
 *
 * This is a "fast" extractor that doesn't use LLM - just Ghidra analysis data.
 * LLM summarization is handled separately by SemanticExtractor.
 */
public class StructureExtractor {

    private final Program program;
    private final BinaryKnowledgeGraph graph;
    private final String binaryId;
    private final TaskMonitor monitor;
    private final FunctionSignatureGenerator signatureGenerator;

    // Statistics (thread-safe)
    private final AtomicInteger functionsExtracted = new AtomicInteger(0);
    private final AtomicInteger callEdgesCreated = new AtomicInteger(0);
    private final AtomicInteger refEdgesCreated = new AtomicInteger(0);
    private final AtomicInteger vulnEdgesCreated = new AtomicInteger(0);

    // Decompiler instance (reused for efficiency) - only for single-threaded operations
    private DecompInterface decompiler;

    // Thread pool for parallel extraction (limited to avoid diminishing returns)
    private static final int DEFAULT_THREAD_COUNT = Math.max(2, Runtime.getRuntime().availableProcessors() / 2);
    private ExecutorService extractorPool;

    // Thread-local decompilers for parallel extraction
    private final ConcurrentHashMap<Long, DecompInterface> threadDecompilers = new ConcurrentHashMap<>();

    // Decompilation retry settings
    private static final int DECOMPILE_BASE_TIMEOUT = 30;  // seconds
    private static final int DECOMPILE_MAX_RETRIES = 3;
    private static final int MAX_INFERRED_CALL_EDGES_PER_FUNCTION = 64;
    private static final Pattern HEX_ADDRESS_PATTERN = Pattern.compile("(?i)\\b0x[0-9a-f]{4,16}\\b");
    private static final Pattern IDENTIFIER_PATTERN = Pattern.compile("\\b[A-Za-z_][A-Za-z0-9_:@$]*\\b");
    private static final Map<String, int[]> CALLBACK_API_ARGUMENTS = createCallbackApiArgumentMap();

    // Incremental mode: when true, preserves existing semantic data (summaries, embeddings, flags)
    private boolean incrementalMode = false;

    /**
     * Create a StructureExtractor for a program.
     *
     * @param program The Ghidra program to extract from
     * @param graph   The knowledge graph to populate
     * @param monitor Task monitor for progress/cancellation
     */
    public StructureExtractor(Program program, BinaryKnowledgeGraph graph, TaskMonitor monitor) {
        this.program = program;
        this.graph = graph;
        this.binaryId = graph.getBinaryId();
        this.monitor = monitor;
        this.signatureGenerator = new FunctionSignatureGenerator(program, monitor);
    }

    /**
     * Set incremental mode for non-destructive reindexing.
     *
     * When enabled:
     * - Existing semantic data (summaries, embeddings, flags) is preserved via COALESCE
     * - Only structural data (names, addresses, edges) is updated
     * - Nodes are marked stale only if content actually changed
     *
     * @param incremental true to enable incremental mode
     */
    public void setIncrementalMode(boolean incremental) {
        this.incrementalMode = incremental;
        if (incremental) {
            Msg.info(this, "StructureExtractor: incremental mode enabled (preserving semantic data)");
        }
    }

    /**
     * Check if incremental mode is enabled.
     */
    public boolean isIncrementalMode() {
        return incrementalMode;
    }

    /**
     * Extract all functions and their relationships.
     * This is the main entry point for graph population.
     *
     * @param includeBlocks Whether to also extract basic blocks (increases graph size)
     * @return ExtractionResult with statistics
     */
    public ExtractionResult extractAll(boolean includeBlocks) {
        long startTime = System.currentTimeMillis();

        try {
            // Initialize decompiler
            decompiler = new DecompInterface();
            decompiler.openProgram(program);

            // Phase 1: Extract all functions as nodes AND their edges
            // Note: extractFunction() also extracts CALLS, REFERENCES, and
            // CALLS_VULNERABLE edges for each function, so we don't need separate bulk phases
            monitor.setMessage("Extracting functions and edges...");
            extractFunctions();

            // Check for cancellation between phases
            if (monitor.isCancelled()) {
                Msg.info(this, "Extraction cancelled after function extraction");
                return new ExtractionResult(functionsExtracted.get(), callEdgesCreated.get(),
                        refEdgesCreated.get(), vulnEdgesCreated.get(),
                        System.currentTimeMillis() - startTime);
            }

            // Phase 2: Create binary-level node
            monitor.setMessage("Creating binary summary node...");
            createBinaryNode();

            if (monitor.isCancelled()) {
                Msg.info(this, "Extraction cancelled after binary node creation");
                return new ExtractionResult(functionsExtracted.get(), callEdgesCreated.get(),
                        refEdgesCreated.get(), vulnEdgesCreated.get(),
                        System.currentTimeMillis() - startTime);
            }

            // Phase 4: Detect communities
            monitor.setMessage("Detecting function communities...");
            detectCommunities();

        } finally {
            if (decompiler != null) {
                decompiler.dispose();
                decompiler = null;
            }
        }

        long elapsed = System.currentTimeMillis() - startTime;
        Msg.info(this, String.format("Structure extraction completed in %dms: %d functions, %d call edges, %d ref edges, %d vuln edges",
                elapsed, functionsExtracted.get(), callEdgesCreated.get(), refEdgesCreated.get(), vulnEdgesCreated.get()));

        return new ExtractionResult(functionsExtracted.get(), callEdgesCreated.get(), refEdgesCreated.get(), vulnEdgesCreated.get(), elapsed);
    }

    /**
     * Extract a single function and its immediate relationships.
     * Used for incremental updates when a new function is discovered.
     *
     * @param function The function to extract
     * @return The created KnowledgeNode, or null on failure
     */
    public KnowledgeNode extractFunction(Function function) {
        if (function == null || function.isThunk()) {
            return null;
        }

        try {
            if (decompiler == null) {
                decompiler = new DecompInterface();
                decompiler.openProgram(program);
            }

            // Check if already cached
            KnowledgeNode existing = graph.getNodeByAddress(function.getEntryPoint().getOffset());
            if (existing != null &&
                existing.getRawContent() != null &&
                existing.getSignature() != null &&
                existing.getDisassembly() != null) {
                // Node exists - but still update edges in case new edge types were added
                updateFunctionEdges(function, existing);
                return existing;
            }

            // Create or update node
            KnowledgeNode node = createFunctionNode(function);
            if (node != null) {
                graph.upsertNode(node);

                // Extract outgoing calls from this function (what it calls)
                extractFunctionCalls(function, node.getId());
                inferFunctionCalls(function, node.getId(), node.getRawContent());

                // Extract incoming calls to this function (what calls it)
                // This ensures callers list is populated for single-function extraction
                extractFunctionCallers(function, node.getId());

                // Extract references from this function (REFERENCES edges)
                extractFunctionReferences(function, node);

                // Extract vulnerable call edges for this function (CALLS_VULNERABLE edges)
                extractFunctionVulnerableCalls(function, node);

                functionsExtracted.incrementAndGet();

                // Flush batched items for single-function extraction
                graph.flushAllBatches();
            }

            return node;
        } catch (Exception e) {
            Msg.error(this, "Failed to extract function " + function.getName() + ": " + e.getMessage());
            return null;
        }
    }

    /**
     * Update edges for an existing function node.
     * Used to add new edge types to already-indexed functions.
     *
     * @param function The function
     * @param node The existing knowledge node
     */
    public void updateFunctionEdges(Function function, KnowledgeNode node) {
        if (function == null || node == null) {
            return;
        }

        try {
            // Check if edges need updating by looking for presence of new edge types
            // We use a simple heuristic: if there are no REFERENCES edges from this node, update
            boolean hasReferencesEdges = graph.hasEdgesOfType(node.getId(), EdgeType.REFERENCES);
            boolean hasVulnerableEdges = graph.hasEdgesOfType(node.getId(), EdgeType.CALLS_VULNERABLE);
            boolean hasInferredCalls = graph.hasEdgesOfType(node.getId(), EdgeType.INFERRED_CALLS);

            if (!hasReferencesEdges) {
                Msg.debug(this, "Updating REFERENCES edges for: " + function.getName());
                extractFunctionReferences(function, node);
            }

            if (!hasInferredCalls) {
                Msg.debug(this, "Updating INFERRED_CALLS edges for: " + function.getName());
                inferFunctionCalls(function, node.getId(), node.getRawContent());
            }

            if (!hasVulnerableEdges) {
                Msg.debug(this, "Updating CALLS_VULNERABLE edges for: " + function.getName());
                extractFunctionVulnerableCalls(function, node);
            }
        } catch (Exception e) {
            Msg.debug(this, "Failed to update edges for " + function.getName() + ": " + e.getMessage());
        }
    }

    /**
     * Get decompiled code for a function, using cache if available.
     * This is the primary caching mechanism to avoid redundant decompilation.
     *
     * @param function The function to decompile
     * @return Decompiled code string, or null on failure
     */
    public String getDecompiledCode(Function function) {
        if (function == null) {
            return null;
        }

        // Check cache first
        String cached = graph.getCachedDecompiledCode(function.getEntryPoint().getOffset());
        if (cached != null) {
            Msg.debug(this, "Cache hit for function: " + function.getName());
            return cached;
        }

        // Decompile and cache
        try {
            if (decompiler == null) {
                decompiler = new DecompInterface();
                decompiler.openProgram(program);
            }

            DecompileResults results = decompiler.decompileFunction(function, 60, monitor);
            if (results != null && results.decompileCompleted()) {
                String code = results.getDecompiledFunction().getC();

                // Cache in graph
                KnowledgeNode node = graph.getNodeByAddress(function.getEntryPoint().getOffset());
                if (node == null) {
                    node = KnowledgeNode.createFunction(
                            binaryId,
                            function.getEntryPoint().getOffset(),
                            function.getName()
                    );
                }
                node.setRawContent(code);
                graph.upsertNode(node);

                Msg.debug(this, "Cached decompiled code for: " + function.getName());
                return code;
            }
        } catch (Exception e) {
            Msg.error(this, "Decompilation failed for " + function.getName() + ": " + e.getMessage());
        }

        return null;
    }

    // ========================================
    // Private extraction methods
    // ========================================

    private void extractFunctions() {
        FunctionManager funcManager = program.getFunctionManager();

        // Collect all functions to process (excluding thunks and externals)
        List<Function> functionsToProcess = new ArrayList<>();
        FunctionIterator functions = funcManager.getFunctions(true);
        while (functions.hasNext()) {
            Function func = functions.next();
            if (!func.isThunk() && !func.isExternal()) {
                functionsToProcess.add(func);
            }
        }

        int actualTotal = functionsToProcess.size();
        Msg.info(this, String.format("Starting parallel extraction of %d functions using %d threads",
                actualTotal, DEFAULT_THREAD_COUNT));

        // Initialize progress monitor with correct total
        monitor.initialize(actualTotal);

        // Create thread pool
        extractorPool = Executors.newFixedThreadPool(DEFAULT_THREAD_COUNT, r -> {
            Thread t = new Thread(r, "StructureExtractor-Worker");
            t.setDaemon(true);
            return t;
        });

        AtomicInteger processed = new AtomicInteger(0);
        List<Future<?>> futures = new ArrayList<>();

        try {
            // Submit all functions to the thread pool
            for (Function func : functionsToProcess) {
                if (monitor.isCancelled()) {
                    break;
                }

                futures.add(extractorPool.submit(() -> {
                    if (monitor.isCancelled()) {
                        return;
                    }

                    try {
                        // Get thread-local decompiler for this worker
                        DecompInterface threadDecompiler = getThreadDecompiler();

                        // Extract function with decompilation
                        extractFunctionParallel(func, threadDecompiler);

                        // Update progress
                        int current = processed.incrementAndGet();
                        if (current % 100 == 0) {
                            monitor.setProgress(current);
                            monitor.setMessage(String.format("Extracting functions... %d/%d", current, actualTotal));
                        }
                    } catch (Exception e) {
                        Msg.debug(StructureExtractor.this, "Error extracting " + func.getName() + ": " + e.getMessage());
                    }
                }));
            }

            // Wait for all tasks to complete (with cancellation support)
            boolean wasCancelled = false;
            outerLoop:
            for (Future<?> future : futures) {
                // Wait for this future with periodic cancellation checks
                while (!future.isDone()) {
                    if (monitor.isCancelled()) {
                        wasCancelled = true;
                        break outerLoop;
                    }
                    try {
                        // Use timeout to allow periodic cancellation checks
                        future.get(100, TimeUnit.MILLISECONDS);
                    } catch (TimeoutException e) {
                        // Continue polling - will check cancellation on next iteration
                        continue;
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                        wasCancelled = true;
                        break outerLoop;
                    } catch (ExecutionException e) {
                        Msg.debug(this, "Task failed: " + e.getCause().getMessage());
                        break; // Move to next future
                    }
                }
            }

            // If cancelled, cancel all pending futures
            if (wasCancelled) {
                Msg.info(this, "Cancellation requested - stopping extraction...");
                for (Future<?> future : futures) {
                    future.cancel(true);
                }
            }
        } finally {
            // Shutdown thread pool - use shutdownNow if cancelled
            if (monitor.isCancelled()) {
                extractorPool.shutdownNow();
            } else {
                extractorPool.shutdown();
            }
            try {
                if (!extractorPool.awaitTermination(5, TimeUnit.SECONDS)) {
                    extractorPool.shutdownNow();
                }
            } catch (InterruptedException e) {
                extractorPool.shutdownNow();
                Thread.currentThread().interrupt();
            }
        }

        // Flush any remaining batched items to database
        graph.flushAllBatches();

        Msg.info(this, String.format("Parallel extraction complete: %d functions processed", processed.get()));
    }

    /**
     * Get or create a decompiler for the current thread.
     */
    private DecompInterface getThreadDecompiler() {
        long threadId = Thread.currentThread().threadId();
        return threadDecompilers.computeIfAbsent(threadId, id -> {
            DecompInterface decomp = new DecompInterface();
            decomp.openProgram(program);
            return decomp;
        });
    }

    /**
     * Extract a function using a provided decompiler (for parallel execution).
     */
    private void extractFunctionParallel(Function function, DecompInterface threadDecompiler) {
        if (function == null || function.isThunk()) {
            return;
        }

        try {
            long address = function.getEntryPoint().getOffset();

            // Check if already cached (synchronized read)
            KnowledgeNode existing = graph.getNodeByAddress(address);
            if (existing != null &&
                existing.getRawContent() != null &&
                existing.getSignature() != null &&
                existing.getDisassembly() != null) {
                // Node exists - update edges in case new edge types were added
                updateFunctionEdges(function, existing);
                return;
            }

            // Create or update node
            KnowledgeNode node = createFunctionNodeParallel(function, threadDecompiler);
            if (node != null) {
                // Queue for batch insert (thread-safe)
                // Use returned node - may be existing canonical node if duplicate
                node = graph.queueNodeForBatch(node);

                // Extract calls from this function (use canonical node ID)
                extractFunctionCalls(function, node.getId());
                inferFunctionCalls(function, node.getId(), node.getRawContent());

                // Extract references from this function (REFERENCES edges)
                extractFunctionReferences(function, node);

                // Extract vulnerable call edges for this function (CALLS_VULNERABLE edges)
                extractFunctionVulnerableCalls(function, node);

                functionsExtracted.incrementAndGet();
            }
        } catch (Exception e) {
            Msg.debug(this, "Failed to extract function " + function.getName() + ": " + e.getMessage());
        }
    }

    /**
     * Attempt to decompile a function with retry logic.
     * @param function The function to decompile
     * @param decompiler The decompiler instance to use
     * @return Decompiled C code, or null if all attempts fail
     */
    private String decompileWithRetry(Function function, DecompInterface decompiler) {
        for (int attempt = 1; attempt <= DECOMPILE_MAX_RETRIES; attempt++) {
            if (monitor.isCancelled()) {
                return null;
            }

            // Increase timeout with each retry: 30s, 60s, 90s
            int timeout = DECOMPILE_BASE_TIMEOUT * attempt;

            try {
                DecompileResults results = decompiler.decompileFunction(function, timeout, monitor);

                if (results != null && results.decompileCompleted()) {
                    DecompiledFunction decompiledFunc = results.getDecompiledFunction();
                    if (decompiledFunc != null) {
                        String code = decompiledFunc.getC();
                        if (code != null && !code.isEmpty()) {
                            if (attempt > 1) {
                                Msg.info(this, "Decompilation succeeded on attempt " + attempt +
                                    " for: " + function.getName());
                            }
                            return code;
                        }
                    }
                }

                // Log failure reason if available
                if (results != null) {
                    String errorMsg = results.getErrorMessage();
                    if (errorMsg != null && !errorMsg.isEmpty()) {
                        Msg.warn(this, "Decompilation attempt " + attempt + " failed for " +
                            function.getName() + ": " + errorMsg);
                    } else {
                        Msg.warn(this, "Decompilation attempt " + attempt + " incomplete for " +
                            function.getName() + " (no error message)");
                    }
                }

            } catch (Exception e) {
                Msg.warn(this, "Decompilation attempt " + attempt + " threw exception for " +
                    function.getName() + ": " + e.getMessage());
            }
        }

        return null;
    }

    /**
     * Create a function node using a provided decompiler (for parallel execution).
     * Uses thread-local decompiler for parallel decompilation.
     *
     * In incremental mode, preserves existing semantic data and only marks stale if content changed.
     */
    private KnowledgeNode createFunctionNodeParallel(Function function, DecompInterface threadDecompiler) {
        try {
            long address = function.getEntryPoint().getOffset();
            String name = function.getName();

            // Check if node already exists
            KnowledgeNode existingNode = graph.getNodeByAddress(address);
            KnowledgeNode node;
            boolean isExistingNode = (existingNode != null);
            String oldName = existingNode != null ? existingNode.getName() : null;

            if (existingNode == null) {
                node = KnowledgeNode.createFunction(binaryId, address, name);
            } else {
                node = existingNode;
                node.setName(name); // Update name in case of rename
            }

            String decompiledCode = null;
            if (threadDecompiler != null) {
                decompiledCode = decompileWithRetry(function, threadDecompiler);
            }

            String disassembly = null;
            try {
                disassembly = getDisassembly(function);
            } catch (Exception e) {
                Msg.error(this, "Disassembly failed for " + function.getName() +
                    ": " + e.getMessage());
            }

            String content = getPrimaryContent(function, decompiledCode, disassembly);
            String signature = signatureGenerator.generate(function);

            // In incremental mode, check if content actually changed before marking stale
            if (incrementalMode && isExistingNode) {
                boolean contentChanged = shouldMarkStale(existingNode, oldName, name, content);
                applyFunctionCodeFields(node, signature, decompiledCode, disassembly, content);
                if (contentChanged) {
                    node.markStale();
                    Msg.debug(this, "Content changed for " + name + ", marking stale");
                } else {
                    // Content unchanged - keep existing content and clear stale flag
                    // (we marked all nodes stale at the start of reindex)
                    node.setStale(false);
                    Msg.debug(this, "Content unchanged for " + name + ", preserving semantic data");
                }
            } else {
                // Non-incremental mode or new node - always update content
                applyFunctionCodeFields(node, signature, decompiledCode, disassembly, content);
                node.markStale();
            }

            // Extract security features (network APIs, file I/O, strings)
            // In incremental mode, only update if we don't already have flags
            if (!incrementalMode || !node.hasSecurityFlags()) {
                extractSecurityFeatures(function, node);
            }

            return node;
        } catch (Exception e) {
            Msg.warn(this, "Failed to create node for " + function.getName() + ": " + e.getMessage());
            return null;
        }
    }

    /**
     * Check if a node's content has changed significantly and needs re-summarization.
     *
     * In incremental mode, we only want to mark nodes stale if:
     * - The function name changed
     * - The decompiled content changed significantly (ignoring whitespace differences)
     *
     * This preserves existing LLM summaries for unchanged functions.
     *
     * @param existing   The existing node from the database
     * @param newName    The new function name from Ghidra
     * @param newContent The new decompiled content
     * @return true if the node should be marked stale for re-summarization
     */
    private boolean shouldMarkStale(KnowledgeNode existing, String newName, String newContent) {
        return shouldMarkStale(existing, existing != null ? existing.getName() : null, newName, newContent);
    }

    private boolean shouldMarkStale(KnowledgeNode existing, String oldName, String newName, String newContent) {
        if (existing == null) {
            return true; // New node, needs summarization
        }

        // User-edited summaries are never overwritten
        if (existing.isUserEdited()) {
            return false;
        }

        // Name changed
        if (!java.util.Objects.equals(oldName, newName)) {
            return true;
        }

        // Content changed (compare normalized, ignoring whitespace)
        String existingNorm = normalizeContent(existing.getRawContent());
        String newNorm = normalizeContent(newContent);
        return !java.util.Objects.equals(existingNorm, newNorm);
    }

    /**
     * Normalize content for comparison by removing excessive whitespace.
     */
    private String normalizeContent(String s) {
        if (s == null) {
            return "";
        }
        return s.replaceAll("\\s+", " ").trim();
    }

    private String getPrimaryContent(Function function, String decompiledCode, String disassembly) {
        if (decompiledCode != null && !decompiledCode.isEmpty()) {
            return decompiledCode;
        }
        if (disassembly != null && !disassembly.isEmpty()) {
            Msg.info(this, "Falling back to disassembly for: " + function.getName());
            return disassembly;
        }

        String fallback = "// Unable to decompile or disassemble: " + function.getName();
        Msg.error(this, "All extraction methods failed for: " + function.getName() +
            " at " + function.getEntryPoint());
        return fallback;
    }

    private void applyFunctionCodeFields(KnowledgeNode node, String signature, String decompiledCode,
                                         String disassembly, String primaryContent) {
        node.setSignature(signature);
        node.setDecompiledCode(decompiledCode);
        node.setDisassembly(disassembly);
        node.setRawContent(primaryContent);
    }

    private KnowledgeNode createFunctionNode(Function function) {
        try {
            long address = function.getEntryPoint().getOffset();
            String name = function.getName();

            // Check if node already exists
            KnowledgeNode existingNode = graph.getNodeByAddress(address);
            KnowledgeNode node;
            boolean isExistingNode = (existingNode != null);
            String oldName = existingNode != null ? existingNode.getName() : null;

            if (existingNode == null) {
                node = KnowledgeNode.createFunction(binaryId, address, name);
            } else {
                node = existingNode;
                node.setName(name); // Update name in case of rename
            }

            String decompiledCode = null;
            DecompileResults results = decompiler.decompileFunction(function, 60, monitor);
            if (results != null && results.decompileCompleted()) {
                decompiledCode = results.getDecompiledFunction().getC();
            }
            String disassembly = getDisassembly(function);
            String content = getPrimaryContent(function, decompiledCode, disassembly);
            String signature = signatureGenerator.generate(function);

            // In incremental mode, check if content actually changed before marking stale
            if (incrementalMode && isExistingNode) {
                boolean contentChanged = shouldMarkStale(existingNode, oldName, name, content);
                applyFunctionCodeFields(node, signature, decompiledCode, disassembly, content);
                if (contentChanged) {
                    node.markStale();
                } else {
                    // Content unchanged - preserve semantic data
                    node.setStale(false);
                }
            } else {
                applyFunctionCodeFields(node, signature, decompiledCode, disassembly, content);
                node.markStale();
            }

            // Extract security features (network APIs, file I/O, strings)
            // In incremental mode, only update if we don't already have flags
            if (!incrementalMode || !node.hasSecurityFlags()) {
                extractSecurityFeatures(function, node);
            }

            return node;
        } catch (Exception e) {
            Msg.warn(this, "Failed to create node for " + function.getName() + ": " + e.getMessage());
            return null;
        }
    }

    /**
     * Extract security-relevant features from a function and apply to node.
     * Also generates and sets security flags for vulnerability tracking.
     * Uses both call graph analysis and decompiled code parsing for better coverage.
     */
    private void extractSecurityFeatures(Function function, KnowledgeNode node) {
        try {
            SecurityFeatureExtractor secExtractor = new SecurityFeatureExtractor(program, monitor);
            // Pass decompiled code for additional API call detection via regex
            String decompiledCode = node.getDecompiledCode();
            SecurityFeatures features = secExtractor.extractFeatures(function, decompiledCode);

            if (!features.isEmpty()) {
                // Apply the raw security features to the node
                node.applySecurityFeatures(features);

                // Generate and set security flags for the graph_nodes.security_flags field
                java.util.List<String> securityFlags = features.generateSecurityFlags();
                if (!securityFlags.isEmpty()) {
                    node.setSecurityFlags(securityFlags);
                    Msg.debug(this, String.format("Security flags for %s: %s",
                            function.getName(), securityFlags));
                }

                Msg.debug(this, String.format("Extracted security features for %s: %s",
                        function.getName(), features.toString()));
            }
        } catch (Exception e) {
            Msg.debug(this, "Failed to extract security features for " + function.getName() + ": " + e.getMessage());
        }
    }

    private void extractCallGraph() {
        FunctionManager funcManager = program.getFunctionManager();
        FunctionIterator functions = funcManager.getFunctions(true);

        while (functions.hasNext() && !monitor.isCancelled()) {
            Function caller = functions.next();
            if (caller.isThunk() || caller.isExternal()) {
                continue;
            }

            KnowledgeNode callerNode = graph.getNodeByAddress(caller.getEntryPoint().getOffset());
            if (callerNode == null) {
                continue;
            }

            extractFunctionCalls(caller, callerNode.getId());
        }
    }

    /**
     * Extract outgoing calls from a function (what this function calls).
     * Uses ReferenceManager to get instruction-level CALL references, which matches
     * what Ghidra's Function Call Trees shows (unlike getCalledFunctions() which misses some).
     */
    private void extractFunctionCalls(Function caller, String callerNodeId) {
        ReferenceManager refMgr = program.getReferenceManager();
        FunctionManager funcMgr = program.getFunctionManager();
        SymbolTable symTable = program.getSymbolTable();
        Set<String> processedTargets = new HashSet<>(); // Avoid duplicate edges

        // Debug logging for specific functions
        boolean debugThis = caller.getName().contains("WorkerThread");

        // Iterate through all addresses in the function body
        AddressSetView body = caller.getBody();
        AddressIterator addrIter = body.getAddresses(true);
        while (addrIter.hasNext() && !monitor.isCancelled()) {
            Address addr = addrIter.next();

            // Get all references FROM this address
            Reference[] refs = refMgr.getReferencesFrom(addr);
            for (Reference ref : refs) {
                // Only process CALL references
                if (!ref.getReferenceType().isCall()) {
                    continue;
                }

                Address toAddr = ref.getToAddress();
                String targetKey = toAddr.toString();
                if (processedTargets.contains(targetKey)) {
                    continue; // Already processed this target
                }
                processedTargets.add(targetKey);

                // Try to resolve to a function
                Function callee = funcMgr.getFunctionAt(toAddr);
                if (callee == null) {
                    callee = funcMgr.getFunctionContaining(toAddr);
                }

                if (callee != null) {
                    // Follow thunks to real function
                    Function realCallee = callee;
                    while (realCallee.isThunk()) {
                        Function thunked = realCallee.getThunkedFunction(true);
                        if (thunked == null) break;
                        realCallee = thunked;
                    }

                    if (realCallee.isExternal()) {
                        if (debugThis) {
                            Msg.info(this, String.format("  [%s] CALL -> EXTERNAL: %s", caller.getName(), realCallee.getName()));
                        }
                        createExternalCallEdge(callerNodeId, realCallee.getName());
                    } else if (realCallee.isThunk()) {
                        // Unresolved thunk - extract name
                        String externalName = extractExternalNameFromThunk(realCallee);
                        if (debugThis) {
                            Msg.info(this, String.format("  [%s] CALL -> THUNK: %s (extracted: %s)",
                                caller.getName(), realCallee.getName(), externalName));
                        }
                        createExternalCallEdge(callerNodeId, externalName);
                    } else {
                        // Internal function
                        if (debugThis) {
                            Msg.info(this, String.format("  [%s] CALL -> INTERNAL: %s", caller.getName(), realCallee.getName()));
                        }
                        createInternalCallEdge(callerNodeId, realCallee);
                    }
                } else {
                    // No function at target - check if it's an external reference
                    Symbol sym = symTable.getPrimarySymbol(toAddr);
                    if (debugThis) {
                        Msg.info(this, String.format("  [%s] CALL -> NO_FUNC at %s, symbol=%s",
                            caller.getName(), toAddr, sym != null ? sym.getName() : "null"));
                    }
                    if (sym != null && sym.isExternalEntryPoint()) {
                        createExternalCallEdge(callerNodeId, sym.getName());
                    } else if (sym != null) {
                        // Has a symbol but not a function - could be IAT entry
                        String name = normalizeExternalName(sym.getName());
                        createExternalCallEdge(callerNodeId, name);
                    }
                    // Else: no symbol, no function - skip this call reference
                }
            }
        }

        if (debugThis) {
            Msg.info(this, String.format("[%s] Total call targets processed: %d", caller.getName(), processedTargets.size()));
        }
    }

    private void inferFunctionCalls(Function caller, String callerNodeId, String content) {
        if (caller == null || callerNodeId == null || content == null || content.isBlank()) {
            return;
        }

        FunctionManager funcMgr = program.getFunctionManager();
        Set<Long> inferredTargets = new HashSet<>();
        Map<String, Function> functionsByName = buildFunctionNameIndex(funcMgr);

        Matcher matcher = HEX_ADDRESS_PATTERN.matcher(content);
        while (matcher.find() && inferredTargets.size() < MAX_INFERRED_CALL_EDGES_PER_FUNCTION) {
            try {
                Function target = resolveFunctionByAddress(funcMgr, matcher.group());
                queueInferredCall(caller, callerNodeId, target, inferredTargets, "address_reference");
            } catch (Exception e) {
                Msg.debug(this, "Failed to infer call from address token: " + e.getMessage());
            }
        }

        inferCallbackApiCalls(caller, callerNodeId, content, funcMgr, functionsByName, inferredTargets);
    }

    private void inferCallbackApiCalls(Function caller, String callerNodeId, String content,
                                       FunctionManager funcMgr, Map<String, Function> functionsByName,
                                       Set<Long> inferredTargets) {
        for (Map.Entry<String, int[]> entry : CALLBACK_API_ARGUMENTS.entrySet()) {
            if (inferredTargets.size() >= MAX_INFERRED_CALL_EDGES_PER_FUNCTION || monitor.isCancelled()) {
                return;
            }

            String apiName = entry.getKey();
            Pattern callPattern = Pattern.compile("(?i)\\b" + Pattern.quote(apiName) + "\\s*\\(");
            Matcher matcher = callPattern.matcher(content);
            while (matcher.find() && inferredTargets.size() < MAX_INFERRED_CALL_EDGES_PER_FUNCTION) {
                int openParen = content.indexOf('(', matcher.start());
                int closeParen = findMatchingParen(content, openParen);
                if (openParen < 0 || closeParen <= openParen) {
                    continue;
                }

                List<String> args = splitArguments(content.substring(openParen + 1, closeParen));
                for (int argIndex : entry.getValue()) {
                    if (argIndex >= args.size()) {
                        continue;
                    }
                    Function target = resolveCallbackArgument(funcMgr, functionsByName, args.get(argIndex));
                    queueInferredCall(caller, callerNodeId, target, inferredTargets,
                            "callback_argument:" + apiName);
                }
            }
        }
    }

    private Map<String, Function> buildFunctionNameIndex(FunctionManager funcMgr) {
        Map<String, Function> index = new HashMap<>();
        FunctionIterator functions = funcMgr.getFunctions(true);
        while (functions.hasNext() && !monitor.isCancelled()) {
            Function function = functions.next();
            if (function == null || function.isExternal() || function.isThunk()) {
                continue;
            }
            addFunctionNameAlias(index, function.getName(), function);
            addFunctionNameAlias(index, function.getName(true), function);
        }
        return index;
    }

    private void addFunctionNameAlias(Map<String, Function> index, String name, Function function) {
        if (name == null || name.isBlank()) {
            return;
        }
        index.putIfAbsent(name.toLowerCase(Locale.ROOT), function);
    }

    private Function resolveCallbackArgument(FunctionManager funcMgr, Map<String, Function> functionsByName,
                                             String argument) {
        if (argument == null || argument.isBlank()) {
            return null;
        }

        Matcher addressMatcher = HEX_ADDRESS_PATTERN.matcher(argument);
        while (addressMatcher.find()) {
            Function target = resolveFunctionByAddress(funcMgr, addressMatcher.group());
            if (target != null) {
                return target;
            }
        }

        Matcher identifierMatcher = IDENTIFIER_PATTERN.matcher(argument);
        Function fallback = null;
        while (identifierMatcher.find()) {
            String token = normalizeCallbackIdentifier(identifierMatcher.group());
            if (token.isBlank() || isCallbackNoiseToken(token)) {
                continue;
            }
            Function target = functionsByName.get(token.toLowerCase(Locale.ROOT));
            if (target != null) {
                return target;
            }
            if (fallback == null) {
                fallback = functionsByName.get(stripNamespace(token).toLowerCase(Locale.ROOT));
            }
        }
        return fallback;
    }

    private Function resolveFunctionByAddress(FunctionManager funcMgr, String addressToken) {
        try {
            String value = addressToken.trim();
            if (value.startsWith("0x") || value.startsWith("0X")) {
                value = value.substring(2);
            }
            long offset = Long.parseUnsignedLong(value, 16);
            Address address = program.getAddressFactory().getDefaultAddressSpace().getAddress(offset);
            Function target = funcMgr.getFunctionAt(address);
            return target != null ? target : funcMgr.getFunctionContaining(address);
        } catch (Exception e) {
            return null;
        }
    }

    private int findMatchingParen(String text, int openParen) {
        if (openParen < 0 || openParen >= text.length() || text.charAt(openParen) != '(') {
            return -1;
        }
        int depth = 0;
        boolean inString = false;
        char stringQuote = 0;
        for (int i = openParen; i < text.length(); i++) {
            char c = text.charAt(i);
            if (inString) {
                if (c == stringQuote && (i == 0 || text.charAt(i - 1) != '\\')) {
                    inString = false;
                }
                continue;
            }
            if (c == '"' || c == '\'') {
                inString = true;
                stringQuote = c;
                continue;
            }
            if (c == '(') {
                depth++;
            } else if (c == ')') {
                depth--;
                if (depth == 0) {
                    return i;
                }
            }
        }
        return -1;
    }

    private List<String> splitArguments(String arguments) {
        List<String> result = new ArrayList<>();
        StringBuilder current = new StringBuilder();
        int depth = 0;
        boolean inString = false;
        char stringQuote = 0;
        for (int i = 0; i < arguments.length(); i++) {
            char c = arguments.charAt(i);
            if (inString) {
                current.append(c);
                if (c == stringQuote && (i == 0 || arguments.charAt(i - 1) != '\\')) {
                    inString = false;
                }
                continue;
            }
            if (c == '"' || c == '\'') {
                inString = true;
                stringQuote = c;
                current.append(c);
                continue;
            }
            if (c == '(' || c == '[' || c == '{') {
                depth++;
            } else if (c == ')' || c == ']' || c == '}') {
                depth = Math.max(0, depth - 1);
            } else if (c == ',' && depth == 0) {
                result.add(current.toString().trim());
                current.setLength(0);
                continue;
            }
            current.append(c);
        }
        if (!current.toString().trim().isEmpty()) {
            result.add(current.toString().trim());
        }
        return result;
    }

    private String normalizeCallbackIdentifier(String token) {
        String normalized = token.trim();
        while (normalized.startsWith("&") || normalized.startsWith("*")) {
            normalized = normalized.substring(1).trim();
        }
        return normalized;
    }

    private boolean isCallbackNoiseToken(String token) {
        String lower = token.toLowerCase(Locale.ROOT);
        return lower.equals("null")
                || lower.equals("0")
                || lower.equals("true")
                || lower.equals("false")
                || lower.equals("sizeof")
                || lower.equals("lpthread_start_routine")
                || lower.equals("pthread_start_routine")
                || lower.equals("thread_proc")
                || lower.equals("void")
                || lower.equals("int")
                || lower.equals("long")
                || lower.equals("undefined")
                || lower.equals("undefined4")
                || lower.equals("undefined8");
    }

    private String stripNamespace(String token) {
        int namespaceIdx = token.lastIndexOf("::");
        if (namespaceIdx >= 0 && namespaceIdx + 2 < token.length()) {
            return token.substring(namespaceIdx + 2);
        }
        int dotIdx = token.lastIndexOf('.');
        return dotIdx >= 0 && dotIdx + 1 < token.length() ? token.substring(dotIdx + 1) : token;
    }

    private static Map<String, int[]> createCallbackApiArgumentMap() {
        Map<String, int[]> map = new LinkedHashMap<>();
        map.put("CreateThread", new int[] {2});
        map.put("CreateRemoteThread", new int[] {3});
        map.put("CreateRemoteThreadEx", new int[] {3});
        map.put("_beginthread", new int[] {0});
        map.put("_beginthreadex", new int[] {2});
        map.put("beginthread", new int[] {0});
        map.put("beginthreadex", new int[] {2});
        map.put("pthread_create", new int[] {2});
        map.put("QueueUserWorkItem", new int[] {0});
        map.put("CreateTimerQueueTimer", new int[] {3});
        map.put("RegisterWaitForSingleObject", new int[] {2});
        map.put("SetTimer", new int[] {3});
        map.put("EnumWindows", new int[] {0});
        map.put("EnumChildWindows", new int[] {1});
        map.put("EnumThreadWindows", new int[] {1});
        map.put("EnumDesktopWindows", new int[] {1});
        map.put("EnumResourceNamesA", new int[] {2});
        map.put("EnumResourceNamesW", new int[] {2});
        map.put("signal", new int[] {1});
        map.put("sigaction", new int[] {1});
        map.put("atexit", new int[] {0});
        map.put("qsort", new int[] {3});
        map.put("bsearch", new int[] {4});
        return Collections.unmodifiableMap(map);
    }

    private void queueInferredCall(Function caller, String callerNodeId, Function target,
                                   Set<Long> inferredTargets, String reason) {
        if (target == null || target.equals(caller) || target.isExternal() || target.isThunk()) {
            return;
        }

        long targetOffset = target.getEntryPoint().getOffset();
        if (!inferredTargets.add(targetOffset)) {
            return;
        }

        KnowledgeNode targetNode = graph.getNodeByAddress(targetOffset);
        if (targetNode == null) {
            targetNode = KnowledgeNode.createFunction(binaryId, targetOffset, target.getName());
            targetNode.markStale();
            targetNode = graph.queueNodeForBatch(targetNode);
        }

        if (graph.hasEdgeBetween(callerNodeId, targetNode.getId(), EdgeType.CALLS)
                || graph.hasEdgeBetween(callerNodeId, targetNode.getId(), EdgeType.INFERRED_CALLS)) {
            return;
        }

        String metadata = "{\"source\":\"" + reason + "\",\"confidence\":\"heuristic\"}";
        graph.queueEdgeForBatch(callerNodeId, targetNode.getId(), EdgeType.INFERRED_CALLS, 0.55, metadata);
    }

    /**
     * Create an edge to an internal function, creating placeholder node if needed.
     */
    private void createInternalCallEdge(String callerNodeId, Function callee) {
        KnowledgeNode calleeNode = graph.getNodeByAddress(callee.getEntryPoint().getOffset());
        if (calleeNode == null) {
            // Create placeholder node for callee that hasn't been processed yet
            calleeNode = KnowledgeNode.createFunction(binaryId,
                    callee.getEntryPoint().getOffset(), callee.getName());
            calleeNode.markStale();
            // Use returned canonical node to ensure correct ID for edge
            calleeNode = graph.queueNodeForBatch(calleeNode);
        }
        graph.queueEdgeForBatch(callerNodeId, calleeNode.getId(), EdgeType.CALLS);
        callEdgesCreated.incrementAndGet();
    }

    /**
     * Normalize external function name by removing common decorations.
     */
    private String normalizeExternalName(String name) {
        if (name == null) return "unknown";

        // Remove __imp_ prefix (Windows import thunk)
        if (name.startsWith("__imp_")) {
            name = name.substring(6);
        }
        // Remove leading underscores (up to 2)
        int count = 0;
        while (name.startsWith("_") && name.length() > 1 && count < 2) {
            name = name.substring(1);
            count++;
        }
        // Remove @N suffix (stdcall decoration)
        int atIdx = name.lastIndexOf('@');
        if (atIdx > 0 && name.substring(atIdx + 1).matches("\\d+")) {
            name = name.substring(0, atIdx);
        }
        return name;
    }

    /**
     * Create an edge to an external function, creating the external node if needed.
     * External functions use null address to avoid unique index conflicts in the database.
     */
    private void createExternalCallEdge(String callerNodeId, String externalName) {
        KnowledgeNode extNode = graph.getNodeByName(externalName);
        boolean created = false;
        if (extNode == null) {
            // Use createExternalFunction which sets address=null (not 0)
            // This avoids unique index conflicts since all externals would have address=0
            extNode = KnowledgeNode.createExternalFunction(binaryId, externalName);
            extNode.setRawContent("// External function: " + externalName);
            // Use returned canonical node to ensure correct ID for edge
            extNode = graph.queueNodeForBatch(extNode);
            created = true;
        }
        // Debug: Log first few external node creations
        if (created && externalName.contains("WSA")) {
            Msg.info(this, String.format("  EXTERNAL NODE CREATED: %s (id=%s, addr=%s)",
                externalName, extNode.getId(), extNode.getAddress()));
        }
        graph.queueEdgeForBatch(callerNodeId, extNode.getId(), EdgeType.CALLS);
    }

    /**
     * Extract external function name from a thunk function name.
     * Handles common decorations:
     * - __imp_WSARecvFrom -> WSARecvFrom
     * - _WSARecvFrom@28 -> WSARecvFrom
     * - thunk_FUN_00401000 -> FUN_00401000
     * - Ordinal_123 -> Ordinal_123 (preserved)
     */
    private String extractExternalNameFromThunk(Function thunk) {
        String name = thunk.getName();
        if (name == null) {
            return "unknown_thunk";
        }

        // Remove __imp_ prefix (Windows import thunk)
        if (name.startsWith("__imp_")) {
            name = name.substring(6);
        }
        // Remove thunk_ prefix
        if (name.startsWith("thunk_")) {
            name = name.substring(6);
        }
        // Remove leading underscores (up to 2, common in Windows APIs)
        int underscoreCount = 0;
        while (name.startsWith("_") && name.length() > 1 && underscoreCount < 2) {
            name = name.substring(1);
            underscoreCount++;
        }
        // Remove @N suffix (stdcall parameter size decoration)
        int atIdx = name.lastIndexOf('@');
        if (atIdx > 0) {
            String suffix = name.substring(atIdx + 1);
            if (suffix.matches("\\d+")) {
                name = name.substring(0, atIdx);
            }
        }

        return name;
    }

    /**
     * Extract incoming calls to a function (what calls this function).
     * This ensures the callers list is populated for single-function extraction.
     */
    private void extractFunctionCallers(Function callee, String calleeNodeId) {
        Set<Function> callingFunctions = callee.getCallingFunctions(monitor);

        for (Function caller : callingFunctions) {
            if (monitor.isCancelled()) {
                break;
            }

            // Skip thunks - follow to real function
            Function realCaller = caller;
            while (realCaller.isThunk()) {
                Function thunked = realCaller.getThunkedFunction(true);
                if (thunked == null) break;
                realCaller = thunked;
            }

            // Skip external callers (shouldn't happen but be safe)
            if (realCaller.isExternal()) {
                continue;
            }

            KnowledgeNode callerNode = graph.getNodeByAddress(realCaller.getEntryPoint().getOffset());
            if (callerNode == null) {
                // Create placeholder node for caller that hasn't been processed yet
                callerNode = KnowledgeNode.createFunction(binaryId,
                        realCaller.getEntryPoint().getOffset(), realCaller.getName());
                callerNode.markStale();
                // Use returned canonical node to ensure correct ID for edge
                callerNode = graph.queueNodeForBatch(callerNode);
            }

            // Create edge: caller -> this function (callee)
            // Check if edge already exists to avoid duplicates
            if (!graph.hasEdgeBetween(callerNode.getId(), calleeNodeId, EdgeType.CALLS)) {
                graph.queueEdgeForBatch(callerNode.getId(), calleeNodeId, EdgeType.CALLS);
                callEdgesCreated.incrementAndGet();
            }
        }
    }

    /**
     * Extract cross-references from functions to data and other code.
     * Creates REFERENCES edges for non-call references.
     */
    private void extractReferences() {
        try {
            ReferenceManager refMgr = program.getReferenceManager();
            FunctionManager funcMgr = program.getFunctionManager();
            FunctionIterator functions = funcMgr.getFunctions(true);

            int total = funcMgr.getFunctionCount();
            int processed = 0;

            // Initialize progress for this phase
            monitor.initialize(total);

            while (functions.hasNext() && !monitor.isCancelled()) {
                Function func = functions.next();
                processed++;

                if (processed % 100 == 0) {
                    monitor.setProgress(processed);
                    monitor.setMessage(String.format("Extracting references... %d/%d", processed, total));
                }

                if (func.isThunk() || func.isExternal()) {
                    continue;
                }

                KnowledgeNode funcNode = graph.getNodeByAddress(func.getEntryPoint().getOffset());
                if (funcNode == null) {
                    continue;
                }

                // Get all references FROM this function's body
                AddressSetView body = func.getBody();
                Set<Long> referencedAddresses = new HashSet<>();

                for (Address addr : body.getAddresses(true)) {
                    if (monitor.isCancelled()) break;

                    Reference[] refs = refMgr.getReferencesFrom(addr);
                    for (Reference ref : refs) {
                        // Skip call references - already handled by CALLS edges
                        if (ref.getReferenceType().isCall()) {
                            continue;
                        }

                        Address toAddr = ref.getToAddress();
                        long toOffset = toAddr.getOffset();

                        // Avoid duplicate edges to same target
                        if (referencedAddresses.contains(toOffset)) {
                            continue;
                        }

                        if (ref.getReferenceType().isData()) {
                            // Code references data - check if it's in a data section
                            MemoryBlock block = program.getMemory().getBlock(toAddr);
                            if (block != null && !block.isExecute()) {
                                // This is a data reference - for now we just track it
                                // We could create DATA nodes if needed in the future
                                referencedAddresses.add(toOffset);
                                refEdgesCreated.incrementAndGet(); // Count it even without creating edge
                            }
                        } else {
                            // Other code references (jumps to other functions, etc.)
                            Function targetFunc = funcMgr.getFunctionContaining(toAddr);
                            if (targetFunc != null && !targetFunc.equals(func)) {
                                KnowledgeNode targetNode = graph.getNodeByAddress(
                                        targetFunc.getEntryPoint().getOffset());
                                if (targetNode != null) {
                                    graph.queueEdgeForBatch(funcNode.getId(), targetNode.getId(), EdgeType.REFERENCES);
                                    referencedAddresses.add(toOffset);
                                    refEdgesCreated.incrementAndGet();
                                }
                            }
                        }
                    }
                }
            }

            Msg.info(this, String.format("Extracted %d reference edges", refEdgesCreated.get()));
        } catch (Exception e) {
            Msg.error(this, "Failed to extract references: " + e.getMessage(), e);
        }
    }

    /**
     * Extract CALLS_VULNERABLE edges from callers to functions with vulnerability risks.
     * Also propagates the CALLS_VULNERABLE_FUNCTION flag to callers.
     */
    private void extractVulnerableCalls() {
        try {
            List<KnowledgeNode> functionNodes = graph.getNodesByType(NodeType.FUNCTION);
            Set<String> processedCallers = new HashSet<>();

            int total = functionNodes.size();
            int processed = 0;

            // Initialize progress for this phase
            monitor.initialize(total);
            monitor.setMessage("Extracting vulnerable call edges...");

            for (KnowledgeNode node : functionNodes) {
                if (monitor.isCancelled()) break;

                processed++;
                if (processed % 100 == 0) {
                    monitor.setProgress(processed);
                    monitor.setMessage(String.format("Extracting vulnerable calls... %d/%d", processed, total));
                }

                List<String> flags = node.getSecurityFlags();
                if (flags == null || flags.isEmpty()) {
                    continue;
                }

                // Check if this function has any vulnerability risk flags
                boolean hasVulnRisk = flags.stream().anyMatch(f -> f.endsWith("_RISK"));
                if (!hasVulnRisk) {
                    continue;
                }

                // This function has vulnerability risks - mark all callers
                List<KnowledgeNode> callers = graph.getCallers(node.getId());
                for (KnowledgeNode caller : callers) {
                    // Add CALLS_VULNERABLE edge
                    graph.queueEdgeForBatch(caller.getId(), node.getId(), EdgeType.CALLS_VULNERABLE);
                    vulnEdgesCreated.incrementAndGet();

                    // Add flag to caller if not already processed
                    if (!processedCallers.contains(caller.getId())) {
                        List<String> callerFlags = caller.getSecurityFlags();
                        if (callerFlags == null) {
                            callerFlags = new ArrayList<>();
                        }
                        if (!callerFlags.contains("CALLS_VULNERABLE_FUNCTION")) {
                            callerFlags = new ArrayList<>(callerFlags); // Make mutable copy
                            callerFlags.add("CALLS_VULNERABLE_FUNCTION");
                            caller.setSecurityFlags(callerFlags);
                            graph.queueNodeForBatch(caller);
                        }
                        processedCallers.add(caller.getId());
                    }
                }
            }

            Msg.info(this, String.format("Extracted %d vulnerable call edges", vulnEdgesCreated.get()));
        } catch (Exception e) {
            Msg.error(this, "Failed to extract vulnerable calls: " + e.getMessage(), e);
        }
    }

    // ========================================
    // Single-function edge extraction methods
    // (for on-demand/incremental indexing)
    // ========================================

    /**
     * Extract REFERENCES edges for a single function.
     * Called during on-demand function indexing.
     *
     * @param function The function to extract references from
     * @param funcNode The function's knowledge node
     */
    private void extractFunctionReferences(Function function, KnowledgeNode funcNode) {
        try {
            ReferenceManager refMgr = program.getReferenceManager();
            FunctionManager funcMgr = program.getFunctionManager();
            AddressSetView body = function.getBody();
            Set<Long> referencedAddresses = new HashSet<>();

            for (Address addr : body.getAddresses(true)) {
                if (monitor.isCancelled()) break;

                Reference[] refs = refMgr.getReferencesFrom(addr);
                for (Reference ref : refs) {
                    // Skip call references - already handled by CALLS edges
                    if (ref.getReferenceType().isCall()) {
                        continue;
                    }

                    Address toAddr = ref.getToAddress();
                    long toOffset = toAddr.getOffset();

                    // Avoid duplicate edges to same target
                    if (referencedAddresses.contains(toOffset)) {
                        continue;
                    }

                    if (!ref.getReferenceType().isData()) {
                        // Code references (jumps to other functions, etc.)
                        Function targetFunc = funcMgr.getFunctionContaining(toAddr);
                        if (targetFunc != null && !targetFunc.equals(function)) {
                            KnowledgeNode targetNode = graph.getNodeByAddress(
                                    targetFunc.getEntryPoint().getOffset());
                            if (targetNode != null) {
                                graph.queueEdgeForBatch(funcNode.getId(), targetNode.getId(), EdgeType.REFERENCES);
                                referencedAddresses.add(toOffset);
                                refEdgesCreated.incrementAndGet();
                            }
                        }
                    }
                }
            }
        } catch (Exception e) {
            Msg.debug(this, "Failed to extract references for " + function.getName() + ": " + e.getMessage());
        }
    }

    /**
     * Extract CALLS_VULNERABLE edges for a single function.
     * If this function has vulnerability risks, marks its callers.
     * Also checks if this function calls vulnerable functions.
     *
     * @param function The function to analyze
     * @param funcNode The function's knowledge node
     */
    private void extractFunctionVulnerableCalls(Function function, KnowledgeNode funcNode) {
        try {
            List<String> flags = funcNode.getSecurityFlags();

            // Check if THIS function has vulnerability risks
            boolean hasVulnRisk = flags != null && flags.stream().anyMatch(f -> f.endsWith("_RISK"));

            if (hasVulnRisk) {
                // Mark all callers with CALLS_VULNERABLE edge
                List<KnowledgeNode> callers = graph.getCallers(funcNode.getId());
                for (KnowledgeNode caller : callers) {
                    graph.queueEdgeForBatch(caller.getId(), funcNode.getId(), EdgeType.CALLS_VULNERABLE);
                    vulnEdgesCreated.incrementAndGet();

                    // Add flag to caller
                    List<String> callerFlags = caller.getSecurityFlags();
                    if (callerFlags == null) {
                        callerFlags = new ArrayList<>();
                    }
                    if (!callerFlags.contains("CALLS_VULNERABLE_FUNCTION")) {
                        callerFlags = new ArrayList<>(callerFlags);
                        callerFlags.add("CALLS_VULNERABLE_FUNCTION");
                        caller.setSecurityFlags(callerFlags);
                        graph.queueNodeForBatch(caller);
                    }
                }
            }

            // Also check if this function CALLS any vulnerable functions
            List<KnowledgeNode> callees = graph.getCallees(funcNode.getId());
            for (KnowledgeNode callee : callees) {
                List<String> calleeFlags = callee.getSecurityFlags();
                boolean calleeVuln = calleeFlags != null && calleeFlags.stream().anyMatch(f -> f.endsWith("_RISK"));

                if (calleeVuln) {
                    // This function calls a vulnerable function
                    graph.queueEdgeForBatch(funcNode.getId(), callee.getId(), EdgeType.CALLS_VULNERABLE);
                    vulnEdgesCreated.incrementAndGet();

                    // Add flag to this function
                    if (flags == null) {
                        flags = new ArrayList<>();
                    }
                    if (!flags.contains("CALLS_VULNERABLE_FUNCTION")) {
                        flags = new ArrayList<>(flags);
                        flags.add("CALLS_VULNERABLE_FUNCTION");
                        funcNode.setSecurityFlags(flags);
                        graph.queueNodeForBatch(funcNode);
                    }
                }
            }
        } catch (Exception e) {
            Msg.debug(this, "Failed to extract vulnerable calls for " + function.getName() + ": " + e.getMessage());
        }
    }

    private void createBinaryNode() {
        String programName = program.getName();

        KnowledgeNode binaryNode = KnowledgeNode.createBinary(binaryId, programName);

        // Build binary description
        StringBuilder desc = new StringBuilder();
        desc.append("Binary: ").append(programName).append("\n");
        desc.append("Format: ").append(program.getExecutableFormat()).append("\n");
        desc.append("Language: ").append(program.getLanguage().getLanguageID()).append("\n");
        desc.append("Compiler: ").append(program.getCompiler()).append("\n");
        desc.append("Functions: ").append(program.getFunctionManager().getFunctionCount()).append("\n");

        // Add entry points
        desc.append("\nEntry Points:\n");
        for (Address entry : program.getSymbolTable().getExternalEntryPointIterator()) {
            Function func = program.getFunctionManager().getFunctionAt(entry);
            if (func != null) {
                desc.append("  - ").append(func.getName()).append(" @ ").append(entry).append("\n");
            }
        }

        binaryNode.setRawContent(desc.toString());
        binaryNode.markStale(); // Needs LLM summary
        graph.queueNodeForBatch(binaryNode);

        // Create CONTAINS edges from binary to all functions
        for (KnowledgeNode funcNode : graph.getNodesByType(NodeType.FUNCTION)) {
            graph.queueEdgeForBatch(binaryNode.getId(), funcNode.getId(), EdgeType.CONTAINS);
        }

        // Flush any remaining batched items
        graph.flushAllBatches();
    }

    // ========================================
    // Helper methods
    // ========================================

    private String getDisassembly(Function function) {
        StringBuilder sb = new StringBuilder();
        InstructionIterator instructions = program.getListing().getInstructions(function.getBody(), true);

        while (instructions.hasNext()) {
            Instruction instr = instructions.next();
            sb.append(String.format("%s  %s\n",
                    instr.getAddressString(true, true),
                    instr.toString()));
        }

        return sb.toString();
    }

    private String getBlockDisassembly(CodeBlock block) {
        StringBuilder sb = new StringBuilder();
        InstructionIterator instructions = program.getListing().getInstructions(block, true);

        while (instructions.hasNext()) {
            Instruction instr = instructions.next();
            sb.append(String.format("%s  %s\n",
                    instr.getAddressString(true, true),
                    instr.toString()));
        }

        return sb.toString();
    }

    // ========================================
    // Community Detection
    // ========================================

    /**
     * Detect communities (clusters) of related functions using label propagation.
     */
    private void detectCommunities() {
        try {
            ghidrassist.graphrag.community.CommunityDetector detector =
                    new ghidrassist.graphrag.community.CommunityDetector(graph, monitor);
            int communityCount = detector.detectCommunities();
            Msg.info(this, String.format("Detected %d communities", communityCount));
        } catch (Exception e) {
            Msg.error(this, "Failed to detect communities: " + e.getMessage(), e);
        }
    }

    /**
     * Cleanup resources.
     */
    public void dispose() {
        if (decompiler != null) {
            decompiler.dispose();
            decompiler = null;
        }

        // Dispose thread-local decompilers
        for (DecompInterface decomp : threadDecompilers.values()) {
            try {
                decomp.dispose();
            } catch (Exception e) {
                // Ignore disposal errors
            }
        }
        threadDecompilers.clear();
    }

    // ========================================
    // Result class
    // ========================================

    /**
     * Results from structure extraction.
     */
    public static class ExtractionResult {
        public final int functionsExtracted;
        public final int callEdgesCreated;
        public final int refEdgesCreated;
        public final int vulnEdgesCreated;
        public final long elapsedMs;

        public ExtractionResult(int functions, int calls, int refs, int vulns, long elapsed) {
            this.functionsExtracted = functions;
            this.callEdgesCreated = calls;
            this.refEdgesCreated = refs;
            this.vulnEdgesCreated = vulns;
            this.elapsedMs = elapsed;
        }

        @Override
        public String toString() {
            return String.format("Extracted %d functions, %d call edges, %d ref edges, %d vuln edges in %dms",
                    functionsExtracted, callEdgesCreated, refEdgesCreated, vulnEdgesCreated, elapsedMs);
        }
    }
}
