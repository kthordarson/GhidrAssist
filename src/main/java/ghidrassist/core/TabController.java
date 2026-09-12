package ghidrassist.core;

import ghidra.app.services.GoToService;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;
import ghidra.util.Msg;
import ghidra.util.task.Task;
import ghidra.util.task.TaskLauncher;
import ghidra.util.task.TaskMonitor;
import ghidrassist.AnalysisDB;
import ghidrassist.GhidrAssistPlugin;
import ghidrassist.LlmApi;
import ghidrassist.apiprovider.APIProviderConfig;
import ghidrassist.apiprovider.ReasoningConfig;
import ghidrassist.chat.PersistedChatMessage;
import ghidrassist.services.*;
import ghidrassist.services.RAGManagementService.RAGIndexStats;
import ghidrassist.ui.tabs.*;
import ghidrassist.graphrag.BinaryKnowledgeGraph;
import ghidrassist.graphrag.nodes.EdgeType;
import ghidrassist.graphrag.nodes.KnowledgeNode;
import ghidrassist.graphrag.nodes.NodeType;
import ghidrassist.graphrag.extraction.StructureExtractor;
import ghidrassist.graphrag.extraction.SemanticExtractor;
import ghidrassist.graphrag.extraction.SecurityFeatureExtractor;
import ghidrassist.graphrag.extraction.SecurityFeatures;
import ghidrassist.services.symgraph.SymGraphService;
import ghidrassist.services.symgraph.SymGraphModels.*;
import ghidrassist.workers.*;
import ghidrassist.core.streaming.StreamingMarkdownRenderer;

import com.google.gson.Gson;

import java.sql.Timestamp;
import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.UUID;

import javax.swing.*;
import javax.swing.event.HyperlinkEvent;
import javax.swing.table.DefaultTableModel;
import java.io.File;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

/**
 * Responsibilities:
 * - UI event coordination
 * - Task lifecycle management
 * - Service orchestration
 * - UI state updates
 *
 * Refactored to delegate specialized operations to sub-controllers:
 * - SymGraphController: SymGraph query/push/pull operations
 * - SemanticGraphController: Semantic graph indexing and analysis
 */
public class TabController {

    // File chooser directory memory
    private static File lastDocumentDirectory = null;

    // Services (business logic)
    private final CodeAnalysisService codeAnalysisService;
    private final QueryService queryService;
    private final ActionAnalysisService actionAnalysisService;
    private final RAGManagementService ragManagementService;
    private final AnalysisDataService analysisDataService;
    private final FeedbackService feedbackService;

    // UI utilities
    private final GhidrAssistPlugin plugin;
    private final MarkdownHelper markdownHelper;

    // Sub-controllers (extracted for decomposition)
    private final SymGraphController symGraphController;
    private final SemanticGraphController semanticGraphController;

    // Shared LLM API instance for cancellation
    private volatile LlmApi currentLlmApi;

    // Line explanation LLM API instance (separate from function explain)
    private volatile LlmApi currentLineExplainLlmApi;

    // ReAct orchestrator for cancellation
    private volatile ghidrassist.agent.react.ReActOrchestrator currentOrchestrator;

    // UI state
    private volatile boolean isQueryRunning;
    private volatile boolean isAgentPlanPending;
    private volatile boolean isLineQueryRunning;
    private volatile boolean isCancelling;  // Guard against concurrent operations during cancellation
    private volatile ReasoningConfig currentReasoningConfig;  // Current reasoning/thinking effort setting

    // Streaming markdown renderer for incremental HTML updates
    private volatile StreamingMarkdownRenderer currentStreamingRenderer;

    // Streaming markdown renderer for Explain tab (separate from Query tab)
    private volatile StreamingMarkdownRenderer currentExplainStreamingRenderer;

    // Streaming markdown renderer for Line Explanation (separate from Function Explain)
    private volatile StreamingMarkdownRenderer currentLineExplainStreamingRenderer;

    // Scheduler for safety timeouts
    private final ScheduledExecutorService safetyScheduler = Executors.newSingleThreadScheduledExecutor();

    // UI Component references
    private ExplainTab explainTab;
    private QueryTab queryTab;
    private ActionsTab actionsTab;
    private RAGManagementTab ragManagementTab;
    private SettingsTab settingsTab;
    private SemanticGraphTab semanticGraphTab;
    private SymGraphTab symGraphTab;

    private volatile String pendingAgentPlan;
    private volatile String pendingAgentQuery;
    private volatile String pendingAgentInitialContext;
    private volatile String pendingAgentRunId;

    // Database for semantic graph operations
    private final AnalysisDB analysisDB;

    public TabController(GhidrAssistPlugin plugin) {
        this.plugin = plugin;
        this.markdownHelper = new MarkdownHelper();
        this.isQueryRunning = false;
        this.isCancelling = false;
        this.currentReasoningConfig = new ReasoningConfig(); // Default to NONE

        // Initialize services
        this.codeAnalysisService = new CodeAnalysisService(plugin);
        this.queryService = new QueryService(plugin);
        this.actionAnalysisService = new ActionAnalysisService(plugin);
        this.ragManagementService = new RAGManagementService();
        this.analysisDataService = new AnalysisDataService(plugin);
        this.feedbackService = new FeedbackService(plugin);
        this.analysisDB = new AnalysisDB();

        // Initialize sub-controllers
        this.symGraphController = new SymGraphController(plugin, analysisDB, queryService, this::refreshChatHistory);
        this.semanticGraphController = new SemanticGraphController(plugin, analysisDB);

        // Register document chat handler for the ga_add_document tool
        queryService.setDocumentChatHandler((title, content) -> {
            int sessionId = queryService.createDocumentChat(title, content);
            if (sessionId != -1) {
                // Refresh chat history on the Swing EDT
                javax.swing.SwingUtilities.invokeLater(this::refreshChatHistory);
            }
            return sessionId;
        });

        new UIState();
    }

    // ==== UI Component Registration ====

    public void setTabs(ExplainTab explainTab, QueryTab queryTab,
                       ActionsTab actionsTab, RAGManagementTab ragManagementTab) {
        this.explainTab = explainTab;
        this.queryTab = queryTab;
        this.actionsTab = actionsTab;
        this.ragManagementTab = ragManagementTab;
    }

    public void setExplainTab(ExplainTab tab) { this.explainTab = tab; }
    public void setQueryTab(QueryTab tab) {
        this.queryTab = tab;
        queryService.setContextStatusConsumer(status -> {
            if (this.queryTab != null) {
                SwingUtilities.invokeLater(() -> this.queryTab.setContextStatus(status));
            }
        });
        queryService.setPendingApprovalConsumer(pendingApproval -> {
            if (this.queryTab != null) {
                SwingUtilities.invokeLater(() -> {
                    this.queryTab.setPendingApproval(pendingApproval);
                    this.queryTab.setAcceptAllToolsState(
                        queryService.hasActiveProgram(),
                        queryService.isAcceptAllToolsEnabled());
                });
            }
        });
        queryService.setTranscriptUpdateConsumer(sessionId -> {
            if (this.queryTab == null || sessionId != queryService.getCurrentSessionId()) {
                return;
            }
            SwingUtilities.invokeLater(() -> {
                if (currentStreamingRenderer != null) {
                    queryTab.updateStreamingPrefix(queryService.getConversationPrefixHtml());
                    queryTab.setEditEnabled(queryService.canEditLatestAssistantResponse());
                } else {
                    renderCurrentChatSession();
                }
            });
        });
        if (this.queryTab != null) {
            this.queryTab.setContextStatus(queryService.getContextStatusText());
            this.queryTab.setPendingApproval(queryService.getCurrentPendingApprovalView());
            this.queryTab.setAcceptAllToolsState(
                queryService.hasActiveProgram(),
                queryService.isAcceptAllToolsEnabled());
            this.queryTab.setEditEnabled(queryService.canEditLatestAssistantResponse());
        }
    }
    public void setActionsTab(ActionsTab tab) { this.actionsTab = tab; }
    public void setRAGManagementTab(RAGManagementTab tab) { this.ragManagementTab = tab; }
    public void setSemanticGraphTab(SemanticGraphTab tab) {
        this.semanticGraphTab = tab;
        semanticGraphController.setSemanticGraphTab(tab);
    }
    public void setSymGraphTab(SymGraphTab tab) {
        this.symGraphTab = tab;
        symGraphController.setSymGraphTab(tab);
    }
    public void setSettingsTab(SettingsTab tab) { this.settingsTab = tab; }

    // ==== Plugin Access ====

    public GhidrAssistPlugin getPlugin() {
        return plugin;
    }

    // ==== Reasoning Configuration ====

    /**
     * Set the reasoning/thinking effort level.
     * Called by the UI when the user changes the dropdown selection.
     */
    public void setReasoningEffort(String level) {
        this.currentReasoningConfig = ReasoningConfig.fromString(level);

        // Save to database
        try {
            analysisDataService.saveReasoningEffort(level.toLowerCase());
            // Msg.info(this, "Reasoning effort set to: " + level);
        } catch (IllegalStateException e) {
            // No program loaded - just update in-memory config
            Msg.warn(this, "Reasoning effort set to: " + level + " (not saved - no program loaded)");
        }
    }

    /**
     * Get the current reasoning effort level as a string for UI display.
     * Loads from database if available.
     */
    public String getReasoningEffort() {
        // Try to load from database first
        try {
            String savedEffort = analysisDataService.getReasoningEffort();
            if (savedEffort != null && !savedEffort.equalsIgnoreCase("none")) {
                // Update in-memory config to match saved value
                this.currentReasoningConfig = ReasoningConfig.fromString(savedEffort);
                // Return with proper capitalization for UI
                return savedEffort.substring(0, 1).toUpperCase() + savedEffort.substring(1);
            }
        } catch (Exception e) {
            // Fall through to in-memory value
        }

        // Fall back to in-memory config
        if (currentReasoningConfig == null || !currentReasoningConfig.isEnabled()) {
            return "None";
        }
        String effort = currentReasoningConfig.getEffortString();
        return effort != null ? effort.substring(0, 1).toUpperCase() + effort.substring(1) : "None";
    }

    /**
     * Set the max tool calls per iteration.
     * Saves to database for persistence across sessions.
     */
    public void setMaxToolCalls(int maxToolCalls) {
        // Validate range (must be at least 1)
        if (maxToolCalls < 1) {
            maxToolCalls = 10;
        }

        // Save to database
        try {
            analysisDataService.saveMaxToolCalls(maxToolCalls);
            // Msg.info(this, "Max tool calls per iteration set to: " + maxToolCalls);
        } catch (IllegalStateException e) {
            // No program loaded - just log
            Msg.warn(this, "Max tool calls set to: " + maxToolCalls + " (not saved - no program loaded)");
        }
    }

    /**
     * Get the max tool calls per iteration.
     * Loads from database if available.
     */
    public int getMaxToolCalls() {
        // Try to load from database first
        try {
            return analysisDataService.getMaxToolCalls();
        } catch (Exception e) {
            // Fall back to default
            return 10;
        }
    }

    // ==== Code Analysis Operations ====

    public void handleExplainFunction() {
        // Msg.info(this, "handleExplainFunction called, isQueryRunning=" + isQueryRunning);

        if (isQueryRunning) {
            Msg.warn(this, "Query already running, cancelling...");
            cancelCurrentOperation();
            return;
        }

        Function currentFunction = plugin.getCurrentFunction();
        if (currentFunction == null) {
            Msg.showInfo(getClass(), explainTab, "No Function", "No function at current location.");
            return;
        }

        // Msg.info(this, "Explaining function: " + currentFunction.getName());

        try {
            setUIState(true, "Stop", "Processing...");
        } catch (Exception e) {
            Msg.error(this, "Failed to set UI state: " + e.getMessage());
            return;
        }

        // Run in background thread (no modal dialog)
        Thread explainThread = new Thread(() -> {
            try {
                String programHash = plugin.getCurrentProgram().getExecutableSHA256();
                BinaryKnowledgeGraph graph = analysisDB.getKnowledgeGraph(programHash);
                long address = currentFunction.getEntryPoint().getOffset();

                // Step 1: Check if node exists with decompilation, if not extract structure
                KnowledgeNode node = graph.getNodeByAddress(address);
                boolean needsExtraction = (node == null) ||
                    (node.getRawContent() == null || node.getRawContent().isEmpty());

                if (needsExtraction) {
                    // Need to index/re-index this function
                    SwingUtilities.invokeLater(() ->
                        explainTab.setExplanationText("<html><body><i>Indexing function structure...</i></body></html>"));

                    StructureExtractor extractor = new StructureExtractor(
                            plugin.getCurrentProgram(), graph, TaskMonitor.DUMMY);
                    try {
                        node = extractor.extractFunction(currentFunction);

                        // If still no rawContent, try to get decompilation directly
                        if (node != null && (node.getRawContent() == null || node.getRawContent().isEmpty())) {
                            String decompilation = extractor.getDecompiledCode(currentFunction);
                            if (decompilation != null && !decompilation.isEmpty()) {
                                node.setRawContent(decompilation);
                                graph.upsertNode(node);
                            }
                        }
                    } finally {
                        extractor.dispose();
                    }
                }

                // Step 2: Extract security features if not present or incomplete
                boolean needsSecurityAnalysis = node != null && (
                    (node.getSecurityFlags() == null || node.getSecurityFlags().isEmpty()) ||
                    (node.getNetworkAPIs() == null || node.getNetworkAPIs().isEmpty())
                );
                if (needsSecurityAnalysis) {
                    SecurityFeatureExtractor secExtractor = new SecurityFeatureExtractor(
                            plugin.getCurrentProgram(), TaskMonitor.DUMMY);
                    // Pass decompiled code for additional API detection via regex parsing
                    String decompiledCode = node.getRawContent();
                    SecurityFeatures features = secExtractor.extractFeatures(currentFunction, decompiledCode);
                    if (features != null) {
                        node.applySecurityFeatures(features);
                    }
                }

                // Step 3: Always run a fresh LLM query when user clicks Explain Function
                if (node != null) {
                    // Clear previous content before starting new query
                    SwingUtilities.invokeLater(() -> {
                        explainTab.setExplanationText("");
                        explainTab.setMarkdownSource("");
                    });

                    boolean needsSummary = true; // Always run fresh LLM query

                    //Msg.info(this, String.format("Semantic analysis: always running fresh query (hasExistingSummary=%b, isStale=%b, isUserEdited=%b)",node.getLlmSummary() != null && !node.getLlmSummary().isEmpty(), node.isStale(), node.isUserEdited()));

                    if (needsSummary) {
                        // Create semantic extractor
                        APIProviderConfig providerConfig = GhidrAssistPlugin.getCurrentProviderConfig();
                        if (providerConfig == null) {
                            throw new Exception("No LLM provider configured. Please configure an API provider in Analysis Options.");
                        }

                        // Msg.info(this, "Creating SemanticExtractor with provider: " + providerConfig.getType());
                        SemanticExtractor semanticExtractor = new SemanticExtractor(
                                providerConfig.createProvider(), graph, analysisDataService.getContext());

                        // Initialize streaming UI
                        // Note: StreamingMarkdownRenderer already calls invokeLater, so callback runs on EDT
                        currentExplainStreamingRenderer = new StreamingMarkdownRenderer(
                            update -> explainTab.applyRenderUpdate(update),
                            markdownHelper
                        );
                        SwingUtilities.invokeLater(() -> explainTab.initializeForStreaming(""));

                        // Use streaming summarizeNode method
                        // Msg.info(this, "Calling summarizeNodeStreaming...");
                        semanticExtractor.summarizeNodeStreaming(node, new SemanticExtractor.StreamingSummaryCallback() {
                            // Track previously received content to compute deltas
                            private final StringBuilder previousContent = new StringBuilder();

                            @Override
                            public void onStart() {
                                previousContent.setLength(0);
                                // Msg.info(this, "Streaming started for function explain");
                            }

                            @Override
                            public void onPartialSummary(String accumulated) {
                                if (currentExplainStreamingRenderer != null) {
                                    // Compute delta from accumulated content
                                    String prev = previousContent.toString();
                                    String delta;
                                    if (accumulated.startsWith(prev)) {
                                        delta = accumulated.substring(prev.length());
                                    } else {
                                        // Fallback: treat as new content
                                        delta = accumulated;
                                        previousContent.setLength(0);
                                    }
                                    previousContent.append(delta);

                                    if (!delta.isEmpty()) {
                                        currentExplainStreamingRenderer.onChunkReceived(delta);
                                    }
                                }
                            }

                            @Override
                            public void onThinkingStateChanged(boolean thinking) {
                                if (currentExplainStreamingRenderer != null) {
                                    currentExplainStreamingRenderer.setThinking(thinking);
                                }
                            }

                            @Override
                            public void onSummaryComplete(String fullSummary, KnowledgeNode updatedNode) {
                                // Msg.info(this, "Streaming complete for function explain");

                                // Complete streaming
                                if (currentExplainStreamingRenderer != null) {
                                    currentExplainStreamingRenderer.onStreamComplete();
                                    currentExplainStreamingRenderer = null;
                                }

                                // Mark as not stale
                                updatedNode.setStale(false);
                                graph.upsertNode(updatedNode);

                                // Update security info panel only (don't overwrite streamed content)
                                SwingUtilities.invokeLater(() -> {
                                    explainTab.setMarkdownSource(fullSummary);
                                    explainTab.updateSecurityInfo(
                                        updatedNode.getRiskLevel(),
                                        updatedNode.getCategory(),
                                        updatedNode.getActivityProfile(),
                                        updatedNode.getSecurityFlags(),
                                        updatedNode.getNetworkAPIs(),
                                        updatedNode.getFileIOAPIs()
                                    );
                                    setUIState(false, "Explain Function", null);
                                });
                            }

                            @Override
                            public void onError(Throwable error) {
                                Msg.error(this, "Streaming error: " + error.getMessage());
                                currentExplainStreamingRenderer = null;
                                SwingUtilities.invokeLater(() -> {
                                    explainTab.setExplanationText("Error: " + error.getMessage());
                                    setUIState(false, "Explain Function", null);
                                });
                            }

                            @Override
                            public boolean shouldContinue() {
                                return isQueryRunning;
                            }
                        });

                        // Return early - the callback will handle completion
                        return;
                    } else {
                        // Msg.info(this, "Skipping semantic analysis - using existing summary");
                    }

                    // Step 4: Save node to graph (only reached if no summary needed)
                    graph.upsertNode(node);

                    // Step 5: Update display
                    final KnowledgeNode finalNode = node;
                    SwingUtilities.invokeLater(() -> {
                        updateExplainDisplay(finalNode);
                        setUIState(false, "Explain Function", null);
                    });
                } else {
                    SwingUtilities.invokeLater(() -> {
                        explainTab.setExplanationText("Failed to analyze function.");
                        explainTab.clearSecurityInfo();
                        setUIState(false, "Explain Function", null);
                    });
                }

            } catch (Exception e) {
                // Clean up any active streaming renderer
                if (currentExplainStreamingRenderer != null) {
                    currentExplainStreamingRenderer = null;
                }
                SwingUtilities.invokeLater(() -> {
                    Msg.showError(getClass(), explainTab, "Error",
                        "Failed to explain function: " + e.getMessage());
                    setUIState(false, "Explain Function", null);
                });
            }
        }, "GhidrAssist-ExplainFunction");

        explainThread.start();
    }

    /**
     * Update the Explain tab display with data from a KnowledgeNode.
     */
    private void updateExplainDisplay(KnowledgeNode node) {
        if (node == null) {
            explainTab.setExplanationText("");
            explainTab.clearSecurityInfo();
            return;
        }

        // Update main summary
        String summary = node.getLlmSummary();
        if (summary != null && !summary.isEmpty()) {
            explainTab.setExplanationText(markdownHelper.markdownToHtml(summary));
        } else {
            explainTab.setExplanationText("<i>No summary available. Click 'Explain Function' to analyze.</i>");
        }

        // Update security info panel
        explainTab.updateSecurityInfo(
            node.getRiskLevel(),
            node.getCategory(),
            node.getActivityProfile(),
            node.getSecurityFlags(),
            node.getNetworkAPIs(),
            node.getFileIOAPIs()
        );
    }

    public void handleExplainLine() {
        // Msg.info(this, "handleExplainLine called, isLineQueryRunning=" + isLineQueryRunning);

        if (isLineQueryRunning) {
            Msg.info(this, "Line query already running, cancelling...");
            cancelLineExplainOperation();
            return;
        }

        Address currentAddress = plugin.getCurrentAddress();
        if (currentAddress == null) {
            Msg.showInfo(getClass(), explainTab, "No Address", "No address at current location.");
            return;
        }

        Function currentFunction = plugin.getCurrentFunction();
        if (currentFunction == null) {
            Msg.showInfo(getClass(), explainTab, "No Function", "Current address is not within a function.");
            return;
        }

        Program program = plugin.getCurrentProgram();
        if (program == null) {
            return;
        }

        String programHash = program.getExecutableSHA256();
        long lineAddress = currentAddress.getOffset();

        // Determine view type based on current location
        GhidrAssistPlugin.CodeViewType codeViewType = plugin.checkLastActiveCodeView();
        String viewType = (codeViewType == GhidrAssistPlugin.CodeViewType.IS_DECOMPILER) ? "DECOMPILER" : "DISASSEMBLY";
        // Msg.info(this, "ExplainLine: Detected view type: " + viewType + " (codeViewType=" + codeViewType + ")");

        // Check cache first
        AnalysisDB.LineExplanation cached = analysisDB.getLineExplanation(programHash, lineAddress, viewType);
        if (cached != null) {
            // Msg.info(this, "Using cached line explanation for address " + currentAddress);
            SwingUtilities.invokeLater(() -> {
                String html = markdownHelper.markdownToHtml(cached.getExplanation());
                explainTab.setLineExplanationText(html);
            });
            return;
        }

        // Set UI state for line explanation
        isLineQueryRunning = true;
        SwingUtilities.invokeLater(() -> {
            explainTab.setLineButtonText("Stop");
            explainTab.setLineExplanationText("<html><body><i>Extracting line context...</i></body></html>");
        });

        // Run in background thread
        Thread lineExplainThread = new Thread(() -> {
            try {
                // Msg.info(this, "ExplainLine: Starting extraction for address " + currentAddress +" (offset=0x" + Long.toHexString(currentAddress.getOffset()) + ")" +                         ", viewType=" + viewType + ", function=" + currentFunction.getName());

                // Extract line context with 5 lines before/after
                CodeUtils.LineContext lineContext;

                if (viewType.equals("DECOMPILER")) {
                    //Msg.info(this, "ExplainLine: Calling getDecompiledLineWithContext...");
                    lineContext = CodeUtils.getDecompiledLineWithContext(
                            currentAddress, ghidra.util.task.TaskMonitor.DUMMY, program, 5);
                } else {
                    // Msg.info(this, "ExplainLine: Calling getDisassemblyLineWithContext...");
                    lineContext = CodeUtils.getDisassemblyLineWithContext(currentAddress, program, 5);
                }

                if (lineContext == null) {
                    Msg.warn(this, "ExplainLine: lineContext is NULL - extraction failed");
                    SwingUtilities.invokeLater(() -> {
                        explainTab.setLineExplanationText("<html><body><i>Could not extract code (null context). Check Ghidra console for details.</i></body></html>");
                        setLineExplainUIState(false, "Explain Line");
                    });
                    return;
                }

                if (!lineContext.isValid()) {
                    Msg.warn(this, "ExplainLine: lineContext is invalid - currentLine is empty or null");
                    Msg.warn(this, "ExplainLine: currentLine='" + lineContext.getCurrentLine() + "'");
                    SwingUtilities.invokeLater(() -> {
                        explainTab.setLineExplanationText("<html><body><i>Could not extract code (empty line). Check Ghidra console for details.</i></body></html>");
                        setLineExplainUIState(false, "Explain Line");
                    });
                    return;
                }

                // Msg.info(this, "ExplainLine: SUCCESS - extracted line context:");
                // Msg.info(this, "  currentLine: '" + lineContext.getCurrentLine() + "'");
                // Msg.info(this, "  linesBefore (" + (lineContext.getLinesBefore() != null ? lineContext.getLinesBefore().split("\n").length : 0) + " lines)");
                // Msg.info(this, "  linesAfter (" + (lineContext.getLinesAfter() != null ? lineContext.getLinesAfter().split("\n").length : 0) + " lines)");

                // Update UI to show we're generating explanation
                SwingUtilities.invokeLater(() ->
                        explainTab.setLineExplanationText("<html><body><i>Generating explanation...</i></body></html>"));

                // Generate prompt
                String prompt = ghidrassist.graphrag.extraction.ExtractionPrompts.lineExplanationPrompt(
                        lineContext.getCurrentLine(),
                        lineContext.getLinesBefore(),
                        lineContext.getLinesAfter(),
                        lineContext.getFunctionName(),
                        viewType.equals("DECOMPILER")
                );

                // Create LLM API and send request
                APIProviderConfig providerConfig = GhidrAssistPlugin.getCurrentProviderConfig();
                if (providerConfig == null) {
                    throw new Exception("No LLM provider configured.");
                }

                currentLineExplainLlmApi = new LlmApi(providerConfig, plugin);

                // Create response handler
                LlmApi.LlmResponseHandler handler = createLineExplainResponseHandler(
                        programHash,
                        currentFunction.getEntryPoint().getOffset(),
                        lineAddress,
                        viewType,
                        lineContext.getCurrentLine(),
                        lineContext.getLinesBefore(),
                        lineContext.getLinesAfter()
                );

                // Execute streaming request
                currentLineExplainLlmApi.sendRequestAsync(prompt, handler);

            } catch (Exception e) {
                Msg.error(this, "Line explanation failed: " + e.getMessage(), e);
                SwingUtilities.invokeLater(() -> {
                    explainTab.setLineExplanationText("<html><body>Error: " + e.getMessage() + "</body></html>");
                    setLineExplainUIState(false, "Explain Line");
                });
            }
        }, "GhidrAssist-ExplainLine");

        lineExplainThread.start();
    }

    /**
     * Cancel the current line explanation operation.
     */
    private void cancelLineExplainOperation() {
        if (currentLineExplainLlmApi != null) {
            currentLineExplainLlmApi.cancelCurrentRequest();
            currentLineExplainLlmApi = null;
        }

        // Clean up streaming renderer
        if (currentLineExplainStreamingRenderer != null) {
            currentLineExplainStreamingRenderer = null;
        }

        setLineExplainUIState(false, "Explain Line");
    }

    /**
     * Set the line explanation UI state.
     */
    private void setLineExplainUIState(boolean running, String buttonText) {
        isLineQueryRunning = running;
        SwingUtilities.invokeLater(() -> {
            if (explainTab != null) {
                explainTab.setLineButtonText(buttonText);
            }
        });
    }

    /**
     * Create a response handler for line explanation streaming.
     * Uses StreamingMarkdownRenderer for incremental HTML updates.
     */
    private LlmApi.LlmResponseHandler createLineExplainResponseHandler(
            String programHash, long functionAddress, long lineAddress,
            String viewType, String lineContent, String contextBefore, String contextAfter) {

        return new LlmApi.LlmResponseHandler() {
            private final StringBuilder responseBuffer = new StringBuilder();

            @Override
            public void onStart() {
                responseBuffer.setLength(0);

                // Initialize streaming for line explanation pane
                // Note: StreamingMarkdownRenderer already calls invokeLater, so callback runs on EDT
                currentLineExplainStreamingRenderer = new StreamingMarkdownRenderer(
                    update -> explainTab.applyLineRenderUpdate(update),
                    markdownHelper
                );

                SwingUtilities.invokeLater(() -> explainTab.initializeLineExplanationForStreaming());
            }

            @Override
            public void onUpdate(String partialResponse) {
                if (partialResponse == null || partialResponse.isEmpty()) {
                    return;
                }

                // Extract delta from cumulative response
                String currentBuffer = responseBuffer.toString();
                String delta;
                if (partialResponse.startsWith(currentBuffer)) {
                    delta = partialResponse.substring(currentBuffer.length());
                    responseBuffer.append(delta);
                } else {
                    delta = partialResponse;
                    responseBuffer.append(delta);
                }

                // Feed delta to streaming renderer
                if (!delta.isEmpty() && currentLineExplainStreamingRenderer != null) {
                    currentLineExplainStreamingRenderer.onChunkReceived(delta);
                }
            }

            @Override
            public void onComplete(String fullResponse) {
                final String finalResponse = (fullResponse != null && !fullResponse.isEmpty())
                        ? fullResponse : responseBuffer.toString();

                // Complete streaming
                if (currentLineExplainStreamingRenderer != null) {
                    currentLineExplainStreamingRenderer.onStreamComplete();
                    currentLineExplainStreamingRenderer = null;
                }

                // Cache the result
                analysisDB.upsertLineExplanation(
                        programHash, functionAddress, lineAddress,
                        viewType, lineContent, contextBefore, contextAfter,
                        finalResponse
                );

                SwingUtilities.invokeLater(() -> {
                    setLineExplainUIState(false, "Explain Line");
                    currentLineExplainLlmApi = null;
                });
            }

            @Override
            public void onError(Throwable error) {
                // Clean up streaming renderer
                if (currentLineExplainStreamingRenderer != null) {
                    // Try to complete with what we have
                    currentLineExplainStreamingRenderer.onStreamComplete();
                    currentLineExplainStreamingRenderer = null;
                }

                SwingUtilities.invokeLater(() -> {
                    String partialContent = responseBuffer.toString();
                    if (!partialContent.isEmpty()) {
                        String html = markdownHelper.markdownToHtml(partialContent + "\n\n[Error: " + error.getMessage() + "]");
                        explainTab.setLineExplanationText(html);
                    } else {
                        explainTab.setLineExplanationText("<html><body>Error: " + error.getMessage() + "</body></html>");
                    }
                    setLineExplainUIState(false, "Explain Line");
                    currentLineExplainLlmApi = null;
                });
            }

            @Override
            public boolean shouldContinue() {
                return isLineQueryRunning;
            }
        };
    }

    // ==== Query Operations ====

    public void handleQuerySubmit(String query, boolean useRAG, boolean useMCP, boolean useAgentic) {
        // If cancellation is in progress, ignore the click
        if (isCancelling) {
            // Msg.info(this, "Cancellation in progress, please wait...");
            return;
        }

        // If a query is running, cancel it
        if (isQueryRunning) {
            cancelCurrentOperation();
            return;
        }

        if (useAgentic && isAgentPlanPending) {
            refineAgentPlan(query);
            return;
        }

        // Agentic mode requires MCP tools
        if (useAgentic && !useMCP) {
            Msg.showInfo(getClass(), queryTab, "MCP Required",
                "Agentic mode requires MCP tools to be enabled.");
            return;
        }

        setUIState(true, "Stop", null);

        // Route to appropriate handler
        if (useAgentic) {
            handleAgenticQuery(query);
        } else {
            handleRegularQuery(query, useRAG, useMCP);
        }
    }

    private void handleRegularQuery(String query, boolean useRAG, boolean useMCP) {
        Task task = new Task("Query", true, true, true) {
            @Override
            public void run(TaskMonitor monitor) {
                try {
                    QueryService.QueryRequest request = queryService.createQueryRequest(query, useRAG, useMCP);

                    feedbackService.cacheLastInteraction(request.getProcessedQuery(), null);

                    // Use shared LlmApi instance for cancellation support
                    LlmApi llmApi = getCurrentLlmApi();
                    queryService.executeQuery(request, llmApi, createConversationHandler());

                } catch (Exception e) {
                    SwingUtilities.invokeLater(() -> {
                        Msg.showError(getClass(), queryTab, "Error",
                            "Failed to perform query: " + e.getMessage());
                        setUIState(false, "Submit", null);
                        currentLlmApi = null; // Clear on error
                    });
                }
            }
        };

        new TaskLauncher(task, plugin.getTool().getToolFrame());
    }

    private void handleAgenticQuery(String query) {
        final String reactRunId = UUID.randomUUID().toString();

        // Add user query to conversation history and ensure we have a session
        final String processedQuery;
        try {
            processedQuery = ghidrassist.core.QueryProcessor.processMacrosInQuery(query, plugin);
            queryService.addUserQuery(processedQuery);
            queryService.beginReActRun(reactRunId, processedQuery);
        } catch (Exception e) {
            Msg.error(this, "Failed to add query to conversation history: " + e.getMessage(), e);
            setUIState(false, "Submit", null);
            return;
        }

        // Get initial context (decompiled code if available)
        final String initialContext;
        ghidra.program.model.listing.Function currentFunction = plugin.getCurrentFunction();
        if (currentFunction != null) {
            initialContext = ghidrassist.core.CodeUtils.getFunctionCode(currentFunction, ghidra.util.task.TaskMonitor.DUMMY);
        } else {
            initialContext = "";
        }
        final String continuationBridge = queryService.getReActContinuationBridgeMarkdown();
        final String reactInitialContext = (continuationBridge != null && !continuationBridge.isBlank())
            ? "## Prior Investigation Context\n" + continuationBridge + "\n\n## Current Binary Context\n" + initialContext
            : initialContext;

        pendingAgentRunId = reactRunId;
        pendingAgentQuery = processedQuery;
        pendingAgentInitialContext = reactInitialContext;
        pendingAgentPlan = null;
        requestAgentPlan(processedQuery, reactInitialContext, null, null);
    }

    private void requestAgentPlan(String query, String reactInitialContext, String previousPlan, String refinement) {
        String planningPrompt = ghidrassist.agent.react.ReActPrompts.getPlanningPrompt(query, reactInitialContext);
        if (previousPlan != null && !previousPlan.isBlank()) {
            planningPrompt += "\n\n## Previous Proposed Plan\n" + previousPlan + "\n";
        }
        if (refinement != null && !refinement.isBlank()) {
            planningPrompt += "\n\n## User Refinement Request\n" + refinement
                + "\n\nRevise the plan to incorporate this feedback. Return only the updated markdown checklist.";
        } else {
            planningPrompt += "\n\nReturn only the proposed markdown checklist and any brief assumptions needed to execute it.";
        }

        LlmApi plannerApi;
        try {
            plannerApi = getCurrentLlmApi();
        } catch (Exception e) {
            Msg.showError(getClass(), queryTab, "Agentic Planning Error",
                "Failed to initialize LLM provider: " + e.getMessage());
            setUIState(false, "Submit", null);
            return;
        }
        currentLlmApi = plannerApi;
        plannerApi.sendRequestAsync(planningPrompt, new LlmApi.LlmResponseHandler() {
            private final StringBuilder planBuffer = new StringBuilder();

            @Override public void onStart() { planBuffer.setLength(0); }
            @Override public void onUpdate(String partialResponse) { planBuffer.append(partialResponse); }
            @Override public void onComplete(String fullResponse) {
                SwingUtilities.invokeLater(() -> {
                    pendingAgentPlan = (fullResponse != null && !fullResponse.isBlank())
                        ? fullResponse
                        : planBuffer.toString();
                    isAgentPlanPending = true;
                    isQueryRunning = false;
                    queryTab.setSubmitButtonText("Submit");
                    queryTab.setPendingPlan(pendingAgentPlan);
                });
            }
            @Override public void onError(Throwable error) {
                SwingUtilities.invokeLater(() -> {
                    Msg.showError(getClass(), queryTab, "Agentic Planning Error",
                        "Planning failed: " + error.getMessage());
                    setUIState(false, "Submit", null);
                    isAgentPlanPending = false;
                });
            }
            @Override public boolean shouldContinue() {
                return !isCancelling;
            }
        });
    }

    private void executeApprovedAgenticQuery(String query, String reactInitialContext,
                                             String reactRunId, String approvedPlan) {
        setUIState(true, "Stop", null);

        // Container to hold iteration history so it can be accessed in the final result handler
        final StringBuilder[] historyContainer = new StringBuilder[]{new StringBuilder()};

        // Initialize MCP servers if needed
        ghidrassist.mcp2.tools.MCPToolManager toolManager =
            ghidrassist.mcp2.tools.MCPToolManager.getInstance();

        // NOTE: Program context for semantic tools is now handled via ToolRegistry
        // in ReActOrchestrator. MCPToolManager only handles MCP server tools.

        java.util.concurrent.CompletableFuture<Void> initFuture;
        if (!toolManager.isInitialized()) {
            // Msg.info(this, "Initializing MCP servers for agentic analysis...");
            SwingUtilities.invokeLater(() ->
                queryTab.setResponseText("<html><body>Initializing MCP servers...</body></html>"));
            initFuture = toolManager.initializeServers();
        } else {
            initFuture = java.util.concurrent.CompletableFuture.completedFuture(null);
        }

        // Chain the analysis after MCP initialization
        initFuture.thenCompose(v -> {
            // Create ReAct orchestrator with new architecture
            int maxToolRounds = getMaxToolCalls();  // Load user's max tool calls setting
            currentOrchestrator = new ghidrassist.agent.react.ReActOrchestrator(
                    ghidrassist.GhidrAssistPlugin.getCurrentProviderConfig(),
                    plugin,
                    18,  // maxIterations
                    8000,  // contextSummaryThreshold
                    maxToolRounds  // maxToolRounds per iteration
                );

            // Wire document chat handler so the agent can create report chats
            currentOrchestrator.setDocumentChatHandler((title, content) -> {
                int sessionId = queryService.createDocumentChat(title, content);
                if (sessionId != -1) {
                    javax.swing.SwingUtilities.invokeLater(() -> refreshChatHistory());
                }
                return sessionId;
            });
            currentOrchestrator.setToolExecutionObserver(queryService.getTranscriptService());
            currentOrchestrator.setToolApprovalService(queryService.getToolApprovalService());
            currentOrchestrator.setActiveSessionId(queryService.getCurrentSessionId());
            currentOrchestrator.setProgramHashSupplier(this::getProgramHash);
            APIProviderConfig providerConfig = ghidrassist.GhidrAssistPlugin.getCurrentProviderConfig();
            if (providerConfig != null) {
                queryService.beginContextTracking(providerConfig.getName(), providerConfig.getModel());
                currentOrchestrator.setContextWindowListener(
                    queryService.createContextWindowListener(providerConfig.getName(), providerConfig.getModel())
                );
            }

            // Create progress handler for UI updates with todos and findings support
            ghidrassist.agent.react.ReActProgressHandler progressHandler =
                createReActProgressHandler(historyContainer, reactRunId, query);

            // Start analysis asynchronously
            return currentOrchestrator.analyze(
                query,
                reactInitialContext,
                String.valueOf(queryService.getCurrentSessionId()),
                progressHandler,
                approvedPlan
            );
        }).thenAccept(result -> {
            // Display result on EDT
            SwingUtilities.invokeLater(() -> {
                // historyContainer[0] now contains the complete investigation including:
                // - All iterations and tool calls
                // - The final synthesis (streamed answer)
                // - Completion metadata (status, iterations, duration)
                // No need to append result.toMarkdown() which would duplicate the answer

                queryService.persistReActFinalAssistantMessage(result.getAnswer());

                // Save ReAct analysis with proper chunking to database
                // Pass the FULL chronological history, not just summaries
                queryService.saveReActAnalysis(
                    query,
                    historyContainer[0].toString(),  // Full investigation details
                    result.getAnswer()
                );

                renderCurrentChatSession();
                queryService.endReActRun(reactRunId);

                // Clear the orchestrator reference
                currentOrchestrator = null;
                setUIState(false, "Submit", null);

                // Refresh chat history to show updated timestamp
                refreshChatHistory();
            });
        }).exceptionally(error -> {
            // Handle errors on EDT - but SAVE progress first!
            String errorMsg = error.getMessage() != null ? error.getMessage() : "Unknown error";
            Msg.error(this, "Agentic analysis failed: " + errorMsg, error);

            SwingUtilities.invokeLater(() -> {
                // Save partial progress even on error/cancellation
                String partialHistory = historyContainer[0].toString();
                if (partialHistory != null && !partialHistory.isEmpty()) {
                    // Determine if this was a cancellation or error
                    boolean isCancellation = errorMsg.toLowerCase().contains("cancel");

                    String suffix = isCancellation ?
                        "\n\n---\n\n**[Analysis cancelled by user]**" :
                        "\n\n---\n\n**[Analysis failed: " + errorMsg + "]**";

                    // Save the partial investigation to database
                    queryService.saveReActAnalysis(
                        query,
                        partialHistory + suffix,
                        isCancellation ? "[Cancelled]" : "[Error: " + errorMsg + "]"
                    );

                    renderCurrentChatSession();

                    // Refresh chat history to show the saved session
                    refreshChatHistory();
                }

                queryService.endReActRun(reactRunId);

                if (!errorMsg.toLowerCase().contains("cancel")) {
                    Msg.showError(getClass(), queryTab, "Agentic Analysis Error",
                        "Analysis failed: " + errorMsg);
                }

                // Clear the orchestrator reference
                currentOrchestrator = null;
                setUIState(false, "Submit", null);
            });
            return null;
        });
    }

    public void handleAgentPlanApproved() {
        if (!isAgentPlanPending || pendingAgentPlan == null || pendingAgentPlan.isBlank()) {
            return;
        }
        String query = pendingAgentQuery;
        String initialContext = pendingAgentInitialContext;
        String runId = pendingAgentRunId;
        String approvedPlan = pendingAgentPlan;

        isAgentPlanPending = false;
        pendingAgentPlan = null;
        if (queryTab != null) {
            queryTab.setPendingPlan(null);
        }
        executeApprovedAgenticQuery(query, initialContext, runId, approvedPlan);
    }

    public void handleAgentPlanCancelled() {
        isAgentPlanPending = false;
        pendingAgentPlan = null;
        if (pendingAgentRunId != null) {
            queryService.endReActRun(pendingAgentRunId);
        }
        pendingAgentRunId = null;
        pendingAgentQuery = null;
        pendingAgentInitialContext = null;
        if (queryTab != null) {
            queryTab.setPendingPlan(null);
        }
        setUIState(false, "Submit", null);
    }

    private void refineAgentPlan(String refinement) {
        if (!isAgentPlanPending || pendingAgentQuery == null || pendingAgentInitialContext == null) {
            return;
        }
        setUIState(true, "Stop", null);
        requestAgentPlan(pendingAgentQuery, pendingAgentInitialContext, pendingAgentPlan, refinement);
    }

    // ==== Action Analysis Operations ====

    public void handleAnalyzeFunction(Map<String, JCheckBox> filterCheckBoxes) {
        // Refresh MCP state before analyzing
        if (queryTab != null) {
            queryTab.refreshMCPState();
        }

        if (isQueryRunning) {
            cancelCurrentOperation();
            return;
        }

        // Extract selected actions
        List<String> selectedActions = new ArrayList<>();
        for (Map.Entry<String, JCheckBox> entry : filterCheckBoxes.entrySet()) {
            if (entry.getValue().isSelected()) {
                selectedActions.add(entry.getKey());
            }
        }

        if (selectedActions.isEmpty()) {
            Msg.showInfo(getClass(), actionsTab, "No Actions Selected",
                "Please select at least one analysis type.");
            return;
        }

        Function currentFunction = plugin.getCurrentFunction();
        if (currentFunction == null) {
            Msg.showInfo(getClass(), actionsTab, "No Function",
                "No function at current location.");
            return;
        }

        setUIState(true, "Stop", null);

        try {
            ActionAnalysisService.ActionAnalysisRequest request =
                actionAnalysisService.createAnalysisRequest(currentFunction, selectedActions);

            actionAnalysisService.executeActionAnalysis(request, createActionAnalysisHandler());

        } catch (Exception e) {
            Msg.showError(this, actionsTab, "Error", e.getMessage());
            setUIState(false, "Analyze Function", null);
        }
    }

    public void handleApplyActions(JTable actionsTable) {
        DefaultTableModel model = (DefaultTableModel) actionsTable.getModel();
        actionAnalysisService.applyActions(model, plugin.getCurrentProgram(), plugin.getCurrentAddress());
    }

    // ==== RAG Management Operations ====

    /**
     * Handle adding documents to RAG index.
     */
    public void handleAddDocuments() {
        JFileChooser fileChooser = createDocumentFileChooser();

        int result = fileChooser.showOpenDialog(ragManagementTab);
        if (result == JFileChooser.APPROVE_OPTION) {
            lastDocumentDirectory = fileChooser.getCurrentDirectory();
            File[] files = fileChooser.getSelectedFiles();
            try {
                ragManagementService.addDocuments(files);
                refreshRAGDocuments();
                Msg.showInfo(this, ragManagementTab, "Success", "Documents added to RAG.");
            } catch (Exception ex) {
                Msg.showError(this, ragManagementTab, "Error",
                        "Failed to ingest documents: " + ex.getMessage());
            }
        }
    }

    /**
     * Handle deleting a single document from RAG index.
     */
    public void handleDeleteDocument(String filename) {
        if (filename == null || filename.isEmpty()) {
            Msg.showInfo(this, ragManagementTab, "No Selection",
                    "No document selected for deletion.");
            return;
        }

        int confirmation = JOptionPane.showConfirmDialog(ragManagementTab,
                "Are you sure you want to delete '" + filename + "'?",
                "Confirm Deletion", JOptionPane.YES_NO_OPTION);

        if (confirmation == JOptionPane.YES_OPTION) {
            try {
                ragManagementService.deleteDocuments(java.util.Collections.singletonList(filename));
                refreshRAGDocuments();
                Msg.showInfo(this, ragManagementTab, "Success",
                        "Document deleted from RAG.");
            } catch (Exception ex) {
                Msg.showError(this, ragManagementTab, "Error",
                        "Failed to delete document: " + ex.getMessage());
            }
        }
    }

    /**
     * Handle clearing the entire RAG index.
     */
    public void handleClearIndex() {
        int confirmation = JOptionPane.showConfirmDialog(ragManagementTab,
                "Are you sure you want to clear the entire RAG index?\nThis will delete all indexed documents.",
                "Confirm Clear Index", JOptionPane.YES_NO_OPTION, JOptionPane.WARNING_MESSAGE);

        if (confirmation == JOptionPane.YES_OPTION) {
            try {
                ragManagementService.clearAllDocuments();
                refreshRAGDocuments();
                if (ragManagementTab != null) {
                    ragManagementTab.clearSearchResults();
                }
                Msg.showInfo(this, ragManagementTab, "Success", "RAG index cleared.");
            } catch (Exception ex) {
                Msg.showError(this, ragManagementTab, "Error",
                        "Failed to clear index: " + ex.getMessage());
            }
        }
    }

    /**
     * Refresh the document table and statistics.
     */
    public void refreshRAGDocuments() {
        if (ragManagementTab == null) {
            return;
        }
        try {
            // Get documents with metadata
            List<RAGDocumentInfo> docs = ragManagementService.getIndexedDocumentsWithInfo();
            ragManagementTab.updateDocumentTable(docs);

            // Get statistics
            RAGIndexStats stats = ragManagementService.getIndexStats();
            ragManagementTab.updateStats(
                    stats.getTotalFiles(),
                    stats.getTotalChunks(),
                    stats.getTotalEmbeddings()
            );
        } catch (Exception ex) {
            Msg.showError(this, ragManagementTab, "Error",
                    "Failed to load indexed files: " + ex.getMessage());
        }
    }

    /**
     * Handle RAG search.
     */
    public void handleRAGSearch(String query, String searchType, RAGManagementTab tab) {
        if (query == null || query.trim().isEmpty()) {
            return;
        }

        try {
            List<SearchResult> results;
            int maxResults = 10;

            switch (searchType) {
                case "Semantic":
                    results = ragManagementService.searchSemantic(query, maxResults);
                    break;
                case "Keyword":
                    results = ragManagementService.searchKeyword(query, maxResults);
                    break;
                case "Hybrid":
                default:
                    results = ragManagementService.searchHybrid(query, maxResults);
                    break;
            }

            tab.displaySearchResults(query, results, searchType);
        } catch (Exception ex) {
            Msg.showError(this, tab, "Search Error",
                    "Failed to perform search: " + ex.getMessage());
        }
    }

    // ==== Analysis Data Operations ====

    public void handleContextSave(String context) {
        try {
            analysisDataService.saveContext(context);
            Msg.showInfo(this, settingsTab, "Success", "Context saved successfully.");
        } catch (Exception e) {
            Msg.showError(this, settingsTab, "Error",
                "Failed to save context: " + e.getMessage());
        }
    }

    public void handleContextLoad() {
        try {
            String currentContext = analysisDataService.getContext();
            if (settingsTab != null) {
                settingsTab.setContextText(currentContext);
                settingsTab.loadReasoningEffort();
                settingsTab.loadMaxToolCalls();
            }
        } catch (Exception e) {
            Msg.showError(this, settingsTab, "Error",
                "Failed to load context: " + e.getMessage());
        }
    }

    public void handleContextRevert() {
        try {
            String defaultContext = analysisDataService.revertToDefaultContext();
            if (settingsTab != null) {
                settingsTab.setContextText(defaultContext);
            }
        } catch (Exception e) {
            Msg.showError(this, settingsTab, "Error",
                "Failed to revert context: " + e.getMessage());
        }
    }

    // ==== Feedback Operations ====

    public void handleApprovalDecision(String requestId, String decision) {
        if (requestId == null || requestId.isBlank()) {
            return;
        }
        boolean resolved = queryService.resolvePendingApproval(requestId, decision);
        if (!resolved) {
            Msg.showInfo(getClass(), null, "Approval",
                "That approval request is no longer pending.");
        }
    }

    public void handleAcceptAllToolsChanged(boolean enabled) {
        if (enabled && queryService.getCurrentSessionId() == -1 && queryService.hasActiveProgram()) {
            int newSessionId = queryService.createNewChatSession();
            if (newSessionId != -1) {
                refreshChatHistory();
                java.util.List<ghidrassist.AnalysisDB.ChatSession> sessions = queryService.getChatSessions();
                for (int i = 0; i < sessions.size(); i++) {
                    if (sessions.get(i).getId() == newSessionId) {
                        queryTab.selectChatSession(i);
                        break;
                    }
                }
            }
        }
        queryService.setAcceptAllToolsEnabled(enabled);
        if (queryTab != null) {
            queryTab.setAcceptAllToolsState(
                queryService.hasActiveProgram(),
                queryService.isAcceptAllToolsEnabled());
        }
    }

    public void handleHyperlinkEvent(HyperlinkEvent e) {
        if (e.getEventType() == HyperlinkEvent.EventType.ACTIVATED) {
            String desc = e.getDescription();

            // Feedback links can appear when viewing old chat content.
            // In that case there may be no in-memory "latest interaction" cached yet.
            if (("thumbsup".equals(desc) || "thumbsdown".equals(desc))
                    && !feedbackService.hasPendingFeedback()) {
                Msg.showInfo(getClass(), null, "Feedback",
                    "No recent response is cached for feedback yet. Run a new query first.");
                return;
            }

            try {
                if (desc.equals("thumbsup")) {
                    feedbackService.storePositiveFeedback();
                    Msg.showInfo(getClass(), null, "Feedback", "Thank you for your positive feedback!");
                } else if (desc.equals("thumbsdown")) {
                    feedbackService.storeNegativeFeedback();
                    Msg.showInfo(getClass(), null, "Feedback", "Thank you for your feedback!");
                } else if (desc.startsWith("tool-expand:") || desc.startsWith("tool-collapse:")) {
                    String correlationId = desc.substring(desc.indexOf(':') + 1);
                    queryService.toggleToolGroupExpansion(correlationId);
                    if (currentStreamingRenderer != null && queryTab != null) {
                        queryTab.updateStreamingPrefix(queryService.getConversationPrefixHtml());
                    } else {
                        renderCurrentChatSession();
                    }
                } else if (desc.startsWith("todo-expand:") || desc.startsWith("todo-collapse:")) {
                    long eventId = Long.parseLong(desc.substring(desc.indexOf(':') + 1));
                    queryService.toggleTodoCardExpansion(eventId);
                    if (currentStreamingRenderer != null && queryTab != null) {
                        queryTab.updateStreamingPrefix(queryService.getConversationPrefixHtml());
                    } else {
                        renderCurrentChatSession();
                    }
                }
            } catch (IllegalStateException ex) {
                Msg.showInfo(getClass(), null, "Feedback", ex.getMessage());
            } catch (Exception ex) {
                Msg.showError(this, null, "Error", "Failed to store feedback: " + ex.getMessage());
            }
        }
    }

    // ==== Location Updates ====

    public void handleLocationUpdate(ProgramLocation loc) {
        if (loc != null && loc.getAddress() != null) {
            // Msg.info(this, "handleLocationUpdate: address=" + loc.getAddress());
            explainTab.updateOffset(loc.getAddress().toString());
            updateAnalysisDisplay();
            updateLineExplanationDisplay(loc.getAddress());
        }
    }

    /**
     * Update the line explanation display when the cursor moves.
     * Shows cached explanation if available, otherwise clears the panel.
     */
    private void updateLineExplanationDisplay(Address address) {
        //Msg.info(this, "updateLineExplanationDisplay: address=" + address);

        if (address == null || explainTab == null) {
            //Msg.info(this, "updateLineExplanationDisplay: address or explainTab is null, returning");
            return;
        }

        // Don't update if a line query is currently running
        if (isLineQueryRunning) {
            //Msg.info(this, "updateLineExplanationDisplay: line query running, skipping");
            return;
        }

        Program program = plugin.getCurrentProgram();
        if (program == null) {
            //Msg.info(this, "updateLineExplanationDisplay: no program, clearing");
            explainTab.clearLineExplanation();
            return;
        }

        // Must be within a function
        Function function = plugin.getCurrentFunction();
        if (function == null) {
            //Msg.info(this, "updateLineExplanationDisplay: no function at address, clearing");
            explainTab.clearLineExplanation();
            return;
        }

        String programHash = program.getExecutableSHA256();
        long lineAddress = address.getOffset();

        // Detect current view type
        GhidrAssistPlugin.CodeViewType codeViewType = plugin.checkLastActiveCodeView();
        String viewType = (codeViewType == GhidrAssistPlugin.CodeViewType.IS_DECOMPILER) ? "DECOMPILER" : "DISASSEMBLY";

        //Msg.info(this, "updateLineExplanationDisplay: Looking up cache for hash=" + programHash.substring(0, 8) + "..., address=0x" + Long.toHexString(lineAddress) + ", viewType=" + viewType);

        // Check for cached explanation for this view type
        AnalysisDB.LineExplanation cached = analysisDB.getLineExplanation(programHash, lineAddress, viewType);
        if (cached != null) {
            //Msg.info(this, "updateLineExplanationDisplay: CACHE HIT - displaying cached explanation");
            String html = markdownHelper.markdownToHtml(cached.getExplanation());
            explainTab.setLineExplanationText(html);
        } else {
            //Msg.info(this, "updateLineExplanationDisplay: CACHE MISS - clearing panel");
            explainTab.clearLineExplanation();
        }
    }

    public void updateAnalysis(ProgramLocation loc) {
        updateAnalysisDisplay();
    }

    public void handleUpdateAnalysis(String updatedContent) {
        Function function = plugin.getCurrentFunction();
        if (function == null) {
            return;
        }

        try {
            String programHash = function.getProgram().getExecutableSHA256();
            BinaryKnowledgeGraph graph = analysisDB.getKnowledgeGraph(programHash);
            KnowledgeNode node = graph.getNodeByAddress(function.getEntryPoint().getOffset());

            if (node == null) {
                Msg.showWarn(this, explainTab, "Not Indexed",
                    "Function not indexed. Run 'Explain Function' first.");
                return;
            }

            node.setLlmSummary(updatedContent);
            node.setUserEdited(true);  // Protect from auto-overwrite
            node.markUpdated();
            graph.upsertNode(node);
        } catch (Exception e) {
            Msg.showError(this, null, "Error", "Failed to update analysis: " + e.getMessage());
        }
    }

    public void handleClearAnalysisData() {
        Function function = plugin.getCurrentFunction();
        if (function == null) {
            return;
        }

        try {
            String programHash = function.getProgram().getExecutableSHA256();
            BinaryKnowledgeGraph graph = analysisDB.getKnowledgeGraph(programHash);
            KnowledgeNode node = graph.getNodeByAddress(function.getEntryPoint().getOffset());

            if (node != null) {
                node.setLlmSummary(null);
                node.setUserEdited(false);
                node.markStale();
                graph.upsertNode(node);
            }

            // Clear all line explanations for this function
            int deletedLines = analysisDB.clearLineExplanationsForFunction(
                programHash, function.getEntryPoint().getOffset()
            );
            if (deletedLines > 0) {
                // Msg.info(this, "Cleared " + deletedLines + " line explanation(s) for function");
            }

            explainTab.setExplanationText("");
            explainTab.clearSecurityInfo();
        } catch (Exception e) {
            Msg.showError(this, null, "Error", "Failed to clear analysis: " + e.getMessage());
        }
    }

    // ==== State Management ====

    public void clearConversationHistory() {
        queryService.clearConversationHistory();
    }

    // ==== Chat History Management ====

    public void handleNewChatSession() {
        // Cancel any running operation first
        if (isQueryRunning) {
            cancelCurrentOperation();
        }
        // Clean up any active streaming renderer
        if (currentStreamingRenderer != null) {
            currentStreamingRenderer = null;
        }

        SwingUtilities.invokeLater(() -> {
            // Clear current conversation and create new session immediately
            queryService.clearConversationHistory();
            queryTab.setResponseText("");
            queryTab.setEditEnabled(false);
            queryTab.clearChatSelection();

            // Create new session immediately instead of waiting for first query
            int newSessionId = queryService.createNewChatSession();
            if (newSessionId != -1) {
                refreshChatHistory();
                // Select the new session in the table
                java.util.List<ghidrassist.AnalysisDB.ChatSession> sessions = queryService.getChatSessions();
                for (int i = 0; i < sessions.size(); i++) {
                    if (sessions.get(i).getId() == newSessionId) {
                        queryTab.selectChatSession(i);
                        break;
                    }
                }
            }
        });
    }

    public void handleDeleteCurrentSession() {
        // Cancel any running operation first
        if (isQueryRunning) {
            cancelCurrentOperation();
        }
        // Clean up any active streaming renderer
        if (currentStreamingRenderer != null) {
            currentStreamingRenderer = null;
        }

        // Get all selected rows from the table (supports multi-select)
        int[] selectedRows = queryTab.getSelectedChatSessions();
        java.util.List<ghidrassist.AnalysisDB.ChatSession> sessions = queryService.getChatSessions();

        int deletedCount = 0;
        if (selectedRows != null && selectedRows.length > 0) {
            // Delete in reverse order to avoid index shifting issues
            for (int i = selectedRows.length - 1; i >= 0; i--) {
                int rowIndex = selectedRows[i];
                if (rowIndex >= 0 && rowIndex < sessions.size()) {
                    int sessionId = sessions.get(rowIndex).getId();
                    if (queryService.deleteSession(sessionId)) {
                        deletedCount++;
                    }
                }
            }
        } else {
            // Fall back to deleting current session if no table selection
            if (queryService.deleteCurrentSession()) {
                deletedCount = 1;
            }
        }

        final boolean anyDeleted = deletedCount > 0;
        SwingUtilities.invokeLater(() -> {
            if (anyDeleted) {
                queryTab.setResponseText("");
                queryTab.setEditEnabled(false);
                queryTab.clearChatSelection();
                refreshChatHistory();
            } else {
                // If no session to delete, just clear the UI
                queryTab.setResponseText("");
                queryTab.setEditEnabled(false);
                queryService.clearConversationHistory();
            }
        });
    }

    public void handleChatSessionSelection(int rowIndex) {
        java.util.List<ghidrassist.AnalysisDB.ChatSession> sessions = queryService.getChatSessions();
        if (rowIndex >= 0 && rowIndex < sessions.size()) {
            ghidrassist.AnalysisDB.ChatSession selectedSession = sessions.get(rowIndex);
            boolean success = queryService.switchToChatSession(selectedSession.getId());

            if (success) {
                SwingUtilities.invokeLater(() -> {
                    renderCurrentChatSession();
                });
            }
        }
    }

    public void handleChatDescriptionUpdate(int rowIndex, String newDescription) {
        java.util.List<ghidrassist.AnalysisDB.ChatSession> sessions = queryService.getChatSessions();
        if (rowIndex >= 0 && rowIndex < sessions.size()) {
            ghidrassist.AnalysisDB.ChatSession session = sessions.get(rowIndex);
            queryService.updateChatDescription(session.getId(), newDescription);
        }
    }

    public void handleChatTypeUpdate(int rowIndex, String newType) {
        java.util.List<ghidrassist.AnalysisDB.ChatSession> sessions = queryService.getChatSessions();
        if (rowIndex >= 0 && rowIndex < sessions.size()) {
            ghidrassist.AnalysisDB.ChatSession session = sessions.get(rowIndex);
            queryService.updateChatType(session.getId(), newType);
        }
    }

    public void refreshChatHistory() {
        if (queryTab != null) {
            java.util.List<ghidrassist.AnalysisDB.ChatSession> sessions = queryService.getChatSessions();
            SwingUtilities.invokeLater(() -> {
                queryTab.updateChatHistory(sessions);
            });
        }
    }

    // ==== Chat Edit Mode Handlers ====

    /**
     * Handle when user clicks Edit button - prepare editable content.
     * @return true if edit mode was successfully entered, false on failure
     */
    public boolean handleChatEditStart() {
        if (queryTab == null) {
            return false;
        }

        int currentSessionId = queryService.getCurrentSessionId();
        if (currentSessionId == -1) {
            Msg.showInfo(this, queryTab, "No Chat",
                    "No active chat session to edit.");
            return false;
        }
        if (!queryService.canEditLatestAssistantResponse()) {
            Msg.showInfo(this, queryTab, "No Assistant Response",
                    "There is no assistant response available to edit yet.");
            return false;
        }
        String editableContent = queryService.getLatestAssistantResponseMarkdown();
        if (editableContent == null) {
            Msg.showInfo(this, queryTab, "No Assistant Response",
                    "There is no assistant response available to edit yet.");
            return false;
        }
        queryTab.setEditableContent(editableContent);
        return true;
    }

    /**
     * Handle when user clicks Save button - parse and apply changes
     */
    public boolean handleChatEditSave(String editedContent) {
        if (queryTab == null || editedContent == null) {
            return false;
        }

        int currentSessionId = queryService.getCurrentSessionId();
        if (currentSessionId == -1) {
            return false;
        }

        if (!queryService.updateLatestAssistantResponseMarkdown(editedContent)) {
            Msg.showError(this, queryTab, "Save Failed",
                "Unable to save the edited assistant response.");
            return false;
        }
        reloadCurrentChat();
        return true;
    }

    /**
     * Reload and display the current chat
     */
    private void reloadCurrentChat() {
        if (queryTab == null) {
            return;
        }

        renderCurrentChatSession();
    }

    /**
     * Get program hash for current program
     */
    private String getProgramHash() {
        if (plugin.getCurrentProgram() != null) {
            return plugin.getCurrentProgram().getExecutableSHA256();
        }
        return null;
    }

    private void renderCurrentChatSession() {
        if (queryTab == null) {
            return;
        }
        queryTab.setResponseText(queryService.getConversationDisplayHtml());
        queryTab.setMarkdownSource(queryService.getConversationHistory());
        queryTab.setEditEnabled(queryService.canEditLatestAssistantResponse());
        queryTab.setContextStatus(queryService.getContextStatusText());
        queryTab.setAcceptAllToolsState(
            queryService.hasActiveProgram(),
            queryService.isAcceptAllToolsEnabled());
        queryTab.setPendingApproval(queryService.getCurrentPendingApprovalView());
    }

    private String sanitizeAssistantResponseForTranscript(String rawResponse) {
        if (rawResponse == null || rawResponse.isBlank()) {
            return rawResponse;
        }

        String sanitized = rawResponse
            .replace("🔄 Starting conversational tool calling (automatic retry on rate limits)...\n\n", "")
            .replace("🔄 Continuing conversation with history...\n\n", "");

        while (sanitized.startsWith("\n")) {
            sanitized = sanitized.substring(1);
        }
        return sanitized;
    }

    private String formatIndexedTimestamp(Long epochMs) {
        if (epochMs == null || epochMs <= 0) {
            return "unknown";
        }
        DateTimeFormatter formatter =
                DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss").withZone(ZoneId.systemDefault());
        return formatter.format(Instant.ofEpochMilli(epochMs));
    }

    public boolean isQueryRunning() {
        return isQueryRunning;
    }

    public void setQueryRunning(boolean running) {
        this.isQueryRunning = running;
    }

    // ==== Private Helper Methods ====

    private LlmApi getCurrentLlmApi() throws Exception {
        APIProviderConfig config = GhidrAssistPlugin.getCurrentProviderConfig();
        if (config == null) {
            throw new Exception("No API provider configured.");
        }

        // Debug: Log current in-memory config before creating API
        if (currentReasoningConfig != null) {
            Msg.info(this, "DEBUG: In-memory reasoning config before create: " +                currentReasoningConfig.getEffort() + ", enabled=" + currentReasoningConfig.isEnabled());
        } else {
            Msg.info(this, "DEBUG: In-memory reasoning config is NULL");
        }

        // Create new instance for this operation
        currentLlmApi = new LlmApi(config, plugin);

        // Load and apply reasoning configuration from database
        try {
            String savedEffort = analysisDataService.getReasoningEffort();
            // Msg.info(this, "DEBUG: Database returned reasoning effort: " + savedEffort);
            // Only override in-memory config if we have a saved non-none value
            // Otherwise keep the current in-memory setting (e.g., when no program is loaded)
            if (savedEffort != null && !savedEffort.equalsIgnoreCase("none")) {
                currentReasoningConfig = ReasoningConfig.fromString(savedEffort);
                Msg.info(this, "DEBUG: Loaded from DB, new config: " + currentReasoningConfig.getEffort());
            } else {
                Msg.info(this, "DEBUG: Keeping in-memory config (DB returned none or null)");
            }
        } catch (Exception e) {
            // Use current in-memory config if database load fails
            Msg.warn(this, "err: Database load failed: " + e.getMessage());
        }

        // Always set reasoning config (even if NONE) to ensure provider has correct state
        if (currentReasoningConfig != null) {
            Msg.info(this, "DEBUG: Setting reasoning config on LlmApi: " +
                currentReasoningConfig.getEffort() + ", enabled=" + currentReasoningConfig.isEnabled());
            currentLlmApi.setReasoningConfig(currentReasoningConfig);
        } else {
            Msg.info(this, "DEBUG: currentReasoningConfig is NULL, setting default NONE");
            currentLlmApi.setReasoningConfig(new ReasoningConfig()); // Default to NONE
        }

        // Verify it was set
        ReasoningConfig verifyConfig = currentLlmApi.getReasoningConfig();
        // Msg.info(this, "DEBUG: Verified LlmApi config after set: " +            verifyConfig.getEffort() + ", enabled=" + verifyConfig.isEnabled());

        return currentLlmApi;
    }

    private void cancelCurrentOperation() {
        // Mark that we're cancelling to prevent concurrent operations
        isCancelling = true;
        if (isAgentPlanPending && queryTab != null) {
            queryTab.setPendingPlan(null);
            isAgentPlanPending = false;
            pendingAgentPlan = null;
        }

        // Clean up streaming renderers FIRST to stop stale UI updates
        if (currentStreamingRenderer != null) {
            currentStreamingRenderer = null;
        }
        if (currentExplainStreamingRenderer != null) {
            currentExplainStreamingRenderer = null;
        }

        // Cancel the ReAct orchestrator if it exists
        if (currentOrchestrator != null) {
            currentOrchestrator.cancel();
            // Don't set to null here - let the completion handler do it
        }

        // Cancel the current LLM API instance if it exists
        if (currentLlmApi != null) {
            currentLlmApi.cancelCurrentRequest();
            // Don't set to null here - let the completion handler do it
        }

        actionAnalysisService.cancelAnalysis();

        // Update button text immediately to show cancellation is in progress
        SwingUtilities.invokeLater(() -> {
            if (queryTab != null) {
                queryTab.setSubmitButtonText("Cancelling...");
            }
        });

        // Schedule a safety reset in case the completion handlers don't fire
        // This prevents the UI from getting stuck if something goes wrong
        safetyScheduler.schedule(() -> {
            if (isCancelling) {
                Msg.warn(this, "Cancellation safety timeout - forcing UI reset");
                SwingUtilities.invokeLater(() -> {
                    isCancelling = false;
                    isQueryRunning = false;
                    currentOrchestrator = null;
                    currentLlmApi = null;
                    currentStreamingRenderer = null;
                    setUIState(false, "Submit", null);
                });
            }
        }, 5, TimeUnit.SECONDS);
    }

    private void setUIState(boolean running, String buttonText, String statusText) {
        isQueryRunning = running;
        // Reset cancellation flag when transitioning to non-running state
        if (!running) {
            isCancelling = false;
        }

        SwingUtilities.invokeLater(() -> {
            if (buttonText != null && explainTab != null) {
                explainTab.setFunctionButtonText(buttonText);
                explainTab.setLineButtonText(buttonText.equals("Stop") ? "Stop" : "Explain Line");
            }
            if (buttonText != null && queryTab != null) {
                queryTab.setSubmitButtonText(buttonText.equals("Stop") ? "Stop" : "Submit");
            }
            if (buttonText != null && actionsTab != null) {
                actionsTab.setAnalyzeFunctionButtonText(buttonText.equals("Stop") ? "Stop" : "Analyze Function");
            }
            if (statusText != null && explainTab != null) {
                explainTab.setExplanationText(statusText);
            }
        });
    }

    private void updateAnalysisDisplay() {
        Function function = plugin.getCurrentFunction();
        if (function == null) {
            explainTab.setExplanationText("");
            explainTab.clearSecurityInfo();
            return;
        }

        try {
            String programHash = function.getProgram().getExecutableSHA256();
            BinaryKnowledgeGraph graph = analysisDB.getKnowledgeGraph(programHash);
            KnowledgeNode node = graph.getNodeByAddress(function.getEntryPoint().getOffset());

            updateExplainDisplay(node);
        } catch (Exception e) {
            // Fall back to empty display on error
            explainTab.setExplanationText("");
            explainTab.clearSecurityInfo();
        }
    }

    private JFileChooser createDocumentFileChooser() {
        JFileChooser fileChooser = new JFileChooser();
        fileChooser.setDialogTitle("Select Documents to Add to RAG");
        fileChooser.setMultiSelectionEnabled(true);
        if (lastDocumentDirectory != null) {
            fileChooser.setCurrentDirectory(lastDocumentDirectory);
        }
        fileChooser.addChoosableFileFilter(
            new javax.swing.filechooser.FileNameExtensionFilter(
                "Text and Markdown Files", "txt", "md"));
        fileChooser.addChoosableFileFilter(
            new javax.swing.filechooser.FileNameExtensionFilter(
                "Source Code", "c", "h", "cpp", "hpp", "py", "java", "rs", "asm"));
        return fileChooser;
    }

    // ==== Response Handler Factories ====

    private LlmApi.LlmResponseHandler createExplainResponseHandler() {
        return new LlmApi.LlmResponseHandler() {
            @Override
            public void onStart() {
                SwingUtilities.invokeLater(() ->
                    explainTab.setExplanationText("Processing..."));
            }

            @Override
            public void onUpdate(String partialResponse) {
                SwingUtilities.invokeLater(() ->
                    explainTab.setExplanationText(
                        markdownHelper.markdownToHtml(partialResponse)));
            }

            @Override
            public void onComplete(String fullResponse) {
                SwingUtilities.invokeLater(() -> {
                    feedbackService.cacheLastInteraction(feedbackService.getLastPrompt(), fullResponse);
                    explainTab.setExplanationText(
                        markdownHelper.markdownToHtml(fullResponse));
                    explainTab.setMarkdownSource(fullResponse);
                    setUIState(false, "Explain Line", null);
                });
            }

            @Override
            public void onError(Throwable error) {
                SwingUtilities.invokeLater(() -> {
                    explainTab.setExplanationText("An error occurred: " + error.getMessage());
                    setUIState(false, "Explain Line", null);
                });
            }

            @Override
            public boolean shouldContinue() {
                return isQueryRunning;
            }
        };
    }

    private LlmApi.LlmResponseHandler createConversationHandler() {
        return new LlmApi.LlmResponseHandler() {
            private final StringBuilder responseBuffer = new StringBuilder();
            private final Object bufferLock = new Object();
            private Timestamp streamingAssistantTimestamp;

            @Override
            public void onStart() {
                synchronized (bufferLock) {
                    responseBuffer.setLength(0);
                }
                streamingAssistantTimestamp = new Timestamp(System.currentTimeMillis());

                // Render existing conversation history as prefix
                String existingHtml = queryService.getConversationPrefixHtml();
                String assistantCardPrefix = queryService.renderStreamingAssistantCardPrefix(streamingAssistantTimestamp);
                String assistantCardSuffix = queryService.renderStreamingAssistantCardSuffix();

                // Create streaming renderer with callback to update UI
                // Note: StreamingMarkdownRenderer already calls invokeLater, so callback runs on EDT
                currentStreamingRenderer = new StreamingMarkdownRenderer(
                    update -> queryTab.applyRenderUpdate(update),
                    markdownHelper
                );
                currentStreamingRenderer.setConversationPrefix(existingHtml);

                // Initialize streaming display with conversation history
                SwingUtilities.invokeLater(() ->
                    queryTab.initializeForStreaming(existingHtml, assistantCardPrefix, assistantCardSuffix));
            }

            @Override
            public void onUpdate(String partialResponse) {
                if (partialResponse == null || partialResponse.isEmpty()) {
                    return;
                }

                String delta;
                synchronized (bufferLock) {
                    // Handle cumulative vs delta responses - extract only new content
                    String currentBuffer = responseBuffer.toString();
                    if (partialResponse.startsWith(currentBuffer)) {
                        delta = partialResponse.substring(currentBuffer.length());
                        if (!delta.isEmpty()) {
                            responseBuffer.append(delta);
                        }
                    } else {
                        delta = partialResponse;
                        responseBuffer.append(delta);
                    }
                }

                // Send delta to streaming renderer for incremental processing
                if (!delta.isEmpty() && currentStreamingRenderer != null) {
                    currentStreamingRenderer.onChunkReceived(delta);
                }
            }

            @Override
            public void onComplete(String fullResponse) {
                synchronized (bufferLock) {
                    // IMPORTANT: Don't clear responseBuffer!
                    // It contains all streaming content including tool calling details.
                    // fullResponse might only contain the final text without tool call history.
                    // Only replace if fullResponse is more complete than current buffer.
                    if (fullResponse != null && fullResponse.length() > responseBuffer.length()) {
                        responseBuffer.setLength(0);
                        responseBuffer.append(fullResponse);
                    }

                    final String finalResponse = sanitizeAssistantResponseForTranscript(responseBuffer.toString());

                    // Signal stream complete to renderer
                    if (currentStreamingRenderer != null) {
                        currentStreamingRenderer.onStreamComplete();
                        currentStreamingRenderer = null;
                    }

                    SwingUtilities.invokeLater(() -> {
                        feedbackService.cacheLastInteraction(feedbackService.getLastPrompt(), finalResponse);
                        if (finalResponse != null && !finalResponse.isBlank()) {
                            queryService.addAssistantResponse(finalResponse);
                        } else {
                            queryService.addError("Model returned no text or tool calls. Check the Ghidra log for provider diagnostics.");
                        }

                        renderCurrentChatSession();
                        setUIState(false, "Submit", null);
                        currentLlmApi = null;

                        refreshChatHistory();
                    });
                }
            }

            @Override
            public void onError(Throwable error) {
                // Clean up streaming renderer
                if (currentStreamingRenderer != null) {
                    currentStreamingRenderer = null;
                }

                // Save partial response if we have content before the error
                synchronized (bufferLock) {
                    if (responseBuffer.length() > 0) {
                        final String partialResponse = responseBuffer.toString();
                        SwingUtilities.invokeLater(() -> {
                            // Save partial response as assistant message before the error
                            queryService.addAssistantMessage(
                                sanitizeAssistantResponseForTranscript(partialResponse) + "\n\n[Incomplete - Error occurred]",
                                queryService.getCurrentProviderType(), null);
                        });
                    }
                }

                SwingUtilities.invokeLater(() -> {
                    queryService.addError(error.getMessage());
                    renderCurrentChatSession();
                    setUIState(false, "Submit", null);
                    currentLlmApi = null;
                });
            }

            @Override
            public boolean shouldContinue() {
                // Check if we should continue - if not, save partial progress
                if (!isQueryRunning) {
                    savePartialResponseOnCancel();
                }
                return isQueryRunning;
            }

            /**
             * Save partial response when cancellation is detected.
             * This ensures we don't lose work even if the user cancels.
             */
            private void savePartialResponseOnCancel() {
                synchronized (bufferLock) {
                    if (responseBuffer.length() > 0) {
                        final String partialResponse = responseBuffer.toString();
                        // Clear buffer to prevent duplicate saves
                        responseBuffer.setLength(0);

                        // Clean up streaming renderer
                        if (currentStreamingRenderer != null) {
                            currentStreamingRenderer = null;
                        }

                        SwingUtilities.invokeLater(() -> {
                            // Save partial response
                            queryService.addAssistantMessage(
                                sanitizeAssistantResponseForTranscript(partialResponse) + "\n\n[Cancelled by user]",
                                queryService.getCurrentProviderType(), null);

                            renderCurrentChatSession();
                            setUIState(false, "Submit", null);
                            currentLlmApi = null;

                            refreshChatHistory();
                        });
                    }
                }
            }
        };
    }

    private ghidrassist.agent.react.ReActProgressHandler createReActProgressHandler(
            final StringBuilder[] historyContainer,
            final String reactRunId,
            final String objective) {
        return new ghidrassist.agent.react.ReActProgressHandler() {
            private final StringBuilder chronologicalHistory = new StringBuilder();
            private final Object historyLock = new Object();
            private String currentIterationOutput = "";
            private final StringBuilder synthesisBuffer = new StringBuilder();
            private boolean synthesisStarted = false;
            private int lastIterationSeen = -1;
            private Timestamp synthesisAssistantTimestamp;

            private void appendHistoryLine(String line) {
                synchronized (historyLock) {
                    chronologicalHistory.append(line).append("\n\n");
                }
            }

            @Override
            public void onStart(String objective) {
                synchronized (historyLock) {
                    chronologicalHistory.setLength(0);
                    chronologicalHistory.append("# ReAct Investigation\n\n");
                    chronologicalHistory.append("**Objective**: ").append(objective).append("\n\n");
                    chronologicalHistory.append("---\n\n");
                    currentIterationOutput = "";
                    lastIterationSeen = -1;
                    synthesisBuffer.setLength(0);
                    synthesisStarted = false;
                }

                queryService.appendReActNotice(
                    "Agentic Investigation",
                    "Planning investigation steps for: " + objective,
                    null,
                    "react_start",
                    reactRunId,
                    objective);
                SwingUtilities.invokeLater(() -> renderCurrentChatSession());
            }

            @Override
            public void onThought(String thought, int iteration) {
                synchronized (historyLock) {
                    if (iteration > lastIterationSeen) {
                        if (!currentIterationOutput.isEmpty()) {
                            chronologicalHistory.append(currentIterationOutput).append("\n\n");
                            chronologicalHistory.append("---\n\n");
                        }
                        chronologicalHistory.append("### Iteration ").append(iteration).append("\n\n");
                        lastIterationSeen = iteration;
                        currentIterationOutput = "";
                    }
                    currentIterationOutput = thought;
                }
            }

            @Override
            public void onAction(String toolName, com.google.gson.JsonObject args) {
                // Tool lifecycle is rendered from transcript observer events.
            }

            @Override
            public void onObservation(String toolName, String result) {
                // Tool lifecycle is rendered from transcript observer events.
            }

            @Override
            public void onIterationStarted(int iteration, String activeTask) {
                appendHistoryLine("### Iteration " + iteration);
                if (activeTask != null && !activeTask.isBlank()) {
                    appendHistoryLine("**Task**: " + activeTask);
                    queryService.appendReActNotice(
                        "Iteration " + iteration,
                        "Working on: " + activeTask,
                        iteration,
                        "iteration_start",
                        reactRunId,
                        objective);
                } else {
                    queryService.appendReActNotice(
                        "Iteration " + iteration,
                        "Continuing investigation",
                        iteration,
                        "iteration_start",
                        reactRunId,
                        objective);
                }
            }

            @Override
            public void onFinding(String finding) {
                synchronized (historyLock) {
                    if (!currentIterationOutput.isEmpty()) {
                        chronologicalHistory.append(currentIterationOutput).append("\n\n");
                        currentIterationOutput = "";
                    }
                    chronologicalHistory.append("💡 **Finding**: ").append(finding).append("\n\n");
                }
                queryService.appendReActFinding(
                    finding,
                    lastIterationSeen > 0 ? lastIterationSeen : null,
                    reactRunId);
            }

            @Override
            public void onComplete(ghidrassist.agent.react.ReActResult result) {
                if (currentStreamingRenderer != null) {
                    currentStreamingRenderer.onStreamComplete();
                    currentStreamingRenderer = null;
                }

                synchronized (historyLock) {
                    if (!currentIterationOutput.isEmpty()) {
                        chronologicalHistory.append(currentIterationOutput).append("\n\n");
                        chronologicalHistory.append("---\n\n");
                        currentIterationOutput = "";
                    }
                    // Archive synthesis buffer if present
                    if (synthesisBuffer.length() > 0) {
                        chronologicalHistory.append(synthesisBuffer).append("\n\n");
                    }

                    // Add completion metadata
                    chronologicalHistory.append("---\n\n");
                    chronologicalHistory.append("**Status**: ").append(result.isSuccess() ? "✓ Complete" : result.getStatus()).append("\n");
                    chronologicalHistory.append("**Iterations**: ").append(result.getIterationCount()).append("\n");
                    chronologicalHistory.append("**Tool Calls**: ").append(result.getToolCallCount()).append("\n");
                    if (result.getDuration() != null) {
                        long seconds = result.getDuration().getSeconds();
                        chronologicalHistory.append("**Duration**: ").append(seconds).append("s\n");
                    }
                    chronologicalHistory.append("\n");

                    historyContainer[0] = chronologicalHistory;
                }
                queryService.appendTranscriptAssistantMessage(
                    result.getAnswer(),
                    reactRunId,
                    objective,
                    result.isSuccess() ? "SUCCESS" : String.valueOf(result.getStatus()));
                queryService.appendReActNotice(
                    "Investigation Complete",
                    String.format("Status: %s | Iterations: %d | Tool calls: %d",
                        result.isSuccess() ? "SUCCESS" : result.getStatus(),
                        result.getIterationCount(),
                        result.getToolCallCount()),
                    null,
                    "completion",
                    reactRunId,
                    objective);
            }

            @Override
            public void onError(Throwable error) {
                if (currentStreamingRenderer != null) {
                    currentStreamingRenderer = null;
                }

                synchronized (historyLock) {
                    chronologicalHistory.append("\n\n❌ **ERROR**: ").append(error.getMessage()).append("\n");
                }
                queryService.appendReActNotice(
                    "Investigation Error",
                    error.getMessage(),
                    lastIterationSeen > 0 ? lastIterationSeen : null,
                    "error",
                    reactRunId,
                    objective);
            }

            @Override
            public boolean shouldContinue() {
                return isQueryRunning;
            }

            @Override
            public void onIterationWarning(int remaining) {
                appendHistoryLine("⚠️ *" + remaining + " iteration(s) remaining*");
                queryService.appendReActNotice(
                    "Iteration Budget",
                    remaining + " iteration(s) remaining",
                    lastIterationSeen > 0 ? lastIterationSeen : null,
                    "iteration_warning",
                    reactRunId,
                    objective);
            }

            @Override
            public void onToolCallWarning(int remaining) {
                appendHistoryLine("⚠️ *" + remaining + " tool call(s) remaining*");
                queryService.appendReActNotice(
                    "Tool Budget",
                    remaining + " tool call(s) remaining",
                    lastIterationSeen > 0 ? lastIterationSeen : null,
                    "tool_warning",
                    reactRunId,
                    objective);
            }

            @Override
            public void onTodosUpdated(String todosFormatted, List<ghidrassist.agent.react.TodoListManager.Todo> todos,
                                       String compactSummary) {
                synchronized (historyLock) {
                    if (!currentIterationOutput.isEmpty()) {
                        chronologicalHistory.append(currentIterationOutput).append("\n\n");
                        currentIterationOutput = "";
                    }
                    chronologicalHistory.append("## 📋 Investigation Progress\n\n");
                    chronologicalHistory.append(todosFormatted).append("\n\n");
                    chronologicalHistory.append("---\n\n");
                }
                queryService.appendReActTodoSnapshot(
                    compactSummary != null ? compactSummary : todosFormatted,
                    todos,
                    lastIterationSeen > 0 ? lastIterationSeen : null,
                    reactRunId,
                    objective);
            }

            @Override
            public void onSummarizing(String summary) {
                synchronized (historyLock) {
                    chronologicalHistory.append("📝 **Summarizing context...**\n\n");
                    chronologicalHistory.append("```\n").append(summary).append("\n```\n\n");
                }
                queryService.appendReActNotice(
                    "Context Summary",
                    summary,
                    lastIterationSeen > 0 ? lastIterationSeen : null,
                    "context_summary",
                    reactRunId,
                    objective);
            }

            @Override
            public void onSynthesisChunk(String chunk) {
                String delta;
                synchronized (historyLock) {
                    if (!synthesisStarted) {
                        if (!currentIterationOutput.isEmpty()) {
                            chronologicalHistory.append(currentIterationOutput).append("\n\n");
                            currentIterationOutput = "";
                        }
                        chronologicalHistory.append("---\n\n");
                        chronologicalHistory.append("## 🎯 Final Analysis\n\n");
                        synthesisStarted = true;
                        synthesisAssistantTimestamp = new Timestamp(System.currentTimeMillis());
                        String prefixHtml = queryService.getConversationPrefixHtml();
                        String assistantCardPrefix =
                            queryService.renderStreamingAssistantCardPrefix(synthesisAssistantTimestamp);
                        String assistantCardSuffix = queryService.renderStreamingAssistantCardSuffix();
                        currentStreamingRenderer = new StreamingMarkdownRenderer(
                            update -> queryTab.applyRenderUpdate(update),
                            markdownHelper);
                        currentStreamingRenderer.setConversationPrefix(prefixHtml);
                        SwingUtilities.invokeLater(() ->
                            queryTab.initializeForStreaming(prefixHtml, assistantCardPrefix, assistantCardSuffix));
                    }

                    String currentBuffer = synthesisBuffer.toString();
                    if (chunk.startsWith(currentBuffer)) {
                        delta = chunk.substring(currentBuffer.length());
                        if (!delta.isEmpty()) {
                            synthesisBuffer.append(delta);
                        }
                    } else {
                        delta = chunk;
                        synthesisBuffer.append(delta);
                    }
                }

                if (!delta.isEmpty() && currentStreamingRenderer != null) {
                    currentStreamingRenderer.onChunkReceived(delta);
                }
            }
        };
    }

    private ActionAnalysisService.ActionAnalysisHandler createActionAnalysisHandler() {
        return new ActionAnalysisService.ActionAnalysisHandler() {
            @Override
            public void onActionStart(String action) {
                SwingUtilities.invokeLater(() -> {
                    actionsTab.setAnalyzeFunctionButtonText("Stop");
                });
            }

            @Override
            public void onActionComplete(String action, String response) {
                SwingUtilities.invokeLater(() -> {
                    try {
                        actionAnalysisService.parseAndDisplayActions(response, actionsTab.getTableModel());
                    } catch (Exception e) {
                        Msg.showError(this, actionsTab, "Error",
                            "Failed to parse actions: " + e.getMessage());
                    }
                });
            }

            @Override
            public void onActionError(String action, Throwable error) {
                SwingUtilities.invokeLater(() -> {
                    Msg.showError(this, actionsTab, "Error",
                        "Action " + action + " failed: " + error.getMessage());
                });
            }

            @Override
            public void onAllActionsComplete() {
                SwingUtilities.invokeLater(() -> {
                    setUIState(false, "Analyze Function", null);
                });
            }

            @Override
            public boolean shouldContinue() {
                return isQueryRunning;
            }
        };
    }

    // ==== Semantic Graph Tab Handlers ====

    /**
     * Update the semantic graph tab when the Ghidra cursor location changes.
     */
    public void updateSemanticGraphLocation(ProgramLocation loc) {
        if (semanticGraphTab == null || loc == null || loc.getAddress() == null) {
            return;
        }

        Function function = plugin.getCurrentFunction();
        String functionName = function != null ?
            ghidrassist.services.symgraph.SymGraphUtils.getQualifiedFunctionName(function) : null;

        // Use function entry point address for graph lookup (nodes are indexed by entry point)
        long address = function != null ?
            function.getEntryPoint().getOffset() :
            loc.getAddress().getOffset();

        SwingUtilities.invokeLater(() -> {
            semanticGraphTab.updateLocation(address, functionName);
        });
    }

    /**
     * Handle navigation to a function/address in the semantic graph tab.
     * Delegates to SemanticGraphController.
     */
    public void handleSemanticGraphGo(String text) {
        semanticGraphController.handleGo(text);
    }

    /**
     * Handle navigation to a specific address.
     * Delegates to SemanticGraphController.
     */
    public void handleSemanticGraphNavigate(long address) {
        semanticGraphController.handleNavigate(address);
    }

    /**
     * Navigate to an address using GoToService.
     */
    private void navigateToAddress(Address addr) {
        GoToService goToService = plugin.getTool().getService(GoToService.class);
        if (goToService != null) {
            goToService.goTo(addr);
        }
    }

    /**
     * Handle reset graph button.
     * Delegates to SemanticGraphController.
     */
    public void handleSemanticGraphReset() {
        semanticGraphController.handleReset();
    }

    /**
     * Handle reindex button with background progress.
     * Delegates to SemanticGraphController.
     */
    public void handleSemanticGraphReindex() {
        semanticGraphController.handleReindex();
    }

    /**
     * Handle refresh names button.
     * Delegates to SemanticGraphController.
     */
    public void handleSemanticGraphRefreshNames() {
        semanticGraphController.handleRefreshNames();
    }

    /**
     * Handle community detection - group related functions.
     * Delegates to SemanticGraphController.
     */
    public void handleSemanticGraphCommunityDetection() {
        semanticGraphController.handleCommunityDetection();
    }

    // ========================================
    // Analysis methods - delegated to SemanticGraphController
    // ========================================

    /**
     * Handle semantic analysis button - LLM summarization of stale nodes.
     * Delegates to SemanticGraphController.
     */
    public void handleSemanticGraphSemanticAnalysis() {
        semanticGraphController.handleSemanticAnalysis();
    }

    public void handleSemanticGraphSemanticAnalysis(ghidrassist.graphrag.SemanticAnalysisOptions options) {
        semanticGraphController.handleSemanticAnalysis(options);
    }

    /**
     * Handle security analysis button - taint analysis + VULNERABLE_VIA edges.
     * Delegates to SemanticGraphController.
     */
    public void handleSemanticGraphSecurityAnalysis() {
        semanticGraphController.handleSecurityAnalysis();
    }

    /**
     * Handle network flow analysis button - trace send/recv data flow paths.
     * Delegates to SemanticGraphController.
     */
    public void handleSemanticGraphNetworkFlowAnalysis() {
        semanticGraphController.handleNetworkFlowAnalysis();
    }

    /**
     * Handle index single function button.
     * Delegates to SemanticGraphController.
     */
    public void handleSemanticGraphIndexFunction(long address) {
        semanticGraphController.handleIndexFunction(address);
    }

    /**
     * Handle list view refresh.
     * Delegates to SemanticGraphController.
     */
    public void handleSemanticGraphListViewRefresh(
            ghidrassist.ui.tabs.semanticgraph.ListViewPanel listView, long address) {
        semanticGraphController.handleListViewRefresh(listView, address);
    }

    /**
     * Handle visual graph refresh.
     * Delegates to SemanticGraphController.
     */
    public void handleSemanticGraphVisualRefresh(
            ghidrassist.ui.tabs.semanticgraph.GraphViewPanel graphView,
            long address, int nHops, java.util.Set<ghidrassist.graphrag.nodes.EdgeType> edgeTypes) {
        semanticGraphController.handleVisualRefresh(graphView, address, nHops, edgeTypes);
    }

    /**
     * Handle adding a security flag.
     * Delegates to SemanticGraphController.
     */
    public void handleSemanticGraphAddFlag(long address, String flag) {
        semanticGraphController.handleAddFlag(address, flag);
    }

    /**
     * Handle removing a security flag.
     * Delegates to SemanticGraphController.
     */
    public void handleSemanticGraphRemoveFlag(long address, String flag) {
        semanticGraphController.handleRemoveFlag(address, flag);
    }

    /**
     * Handle saving LLM summary.
     * Delegates to SemanticGraphController.
     */
    public void handleSemanticGraphSaveSummary(long address, String summary) {
        semanticGraphController.handleSaveSummary(address, summary);
    }

    /**
     * Handle edge click in list view.
     * Delegates to SemanticGraphController.
     */
    public void handleSemanticGraphEdgeClick(String targetId) {
        semanticGraphController.handleEdgeClick(targetId);
    }

    /**
     * Handle semantic graph search query.
     * Delegates to SemanticGraphController.
     */
    public void handleSemanticGraphSearchQuery(String queryType, com.google.gson.JsonObject args,
                                                java.util.function.Consumer<String> resultCallback) {
        semanticGraphController.handleSearchQuery(queryType, args, resultCallback);
    }

    // ==== SymGraph Operations (delegated to SymGraphController) ====

    /**
     * Handle SymGraph query request.
     * Delegates to SymGraphController.
     */
    public void handleSymGraphQuery() {
        symGraphController.handleQuery();
    }

    public void handleSymGraphUpload() {
        symGraphController.handleUploadBinary();
    }

    /**
     * Handle SymGraph push request.
     * Delegates to SymGraphController.
     */
    public void handleSymGraphPush(String scope, boolean pushSymbols, boolean pushGraph, String visibility) {
        symGraphController.handlePush(scope, pushSymbols, pushGraph, visibility);
    }

    /**
     * Build a local push preview before executing a SymGraph push.
     */
    public void handleSymGraphPushPreview() {
        symGraphController.handlePushPreview();
    }

    /**
     * Execute the selected SymGraph push preview.
     */
    public void handleSymGraphExecutePush() {
        symGraphController.handlePush(null, null, null, null);
    }

    /**
     * Handle SymGraph pull preview request.
     * Delegates to SymGraphController.
     */
    public void handleSymGraphPullPreview() {
        symGraphController.handlePullPreview();
    }

    /**
     * Handle applying selected symbols from SymGraph.
     */
    private int getGraphCommunityCount(GraphExport export) {
        if (export == null || export.getMetadata() == null) {
            return 0;
        }
        Object countValue = export.getMetadata().get("community_count");
        if (countValue instanceof Number) {
            return ((Number) countValue).intValue();
        }
        Object communitiesValue = export.getMetadata().get("communities");
        if (communitiesValue instanceof List) {
            return ((List<?>) communitiesValue).size();
        }
        return 0;
    }

    private List<String> getListProperty(Map<String, Object> props, String key) {
        if (props == null) {
            return new ArrayList<>();
        }
        Object value = props.get(key);
        if (value instanceof List) {
            List<String> list = new ArrayList<>();
            for (Object item : (List<?>) value) {
                if (item != null) {
                    list.add(item.toString());
                }
            }
            return list;
        }
        return new ArrayList<>();
    }

    private double getDoubleProperty(Map<String, Object> props, String key, double defaultValue) {
        if (props == null) {
            return defaultValue;
        }
        Object value = props.get(key);
        if (value instanceof Number) {
            return ((Number) value).doubleValue();
        }
        return defaultValue;
    }

    private void mergeGraphData(GraphExport export, String programHash, String mergePolicy) {
        if (export == null) {
            return;
        }
        BinaryKnowledgeGraph graph = analysisDB.getKnowledgeGraph(programHash);
        if ("replace".equals(mergePolicy)) {
            graph.clearGraph();
        }

        Map<Long, String> addressToId = new HashMap<>();
        Map<String, String> endpointToId = new HashMap<>();
        Map<String, String> nameToId = new HashMap<>();
        for (GraphNode node : export.getNodes()) {
            NodeType nodeType = NodeType.fromString(node.getNodeType());
            if (nodeType == null) {
                nodeType = NodeType.FUNCTION;
            }

            KnowledgeNode existing = node.getAddress() == 0 && node.getName() != null
                    ? graph.getNodeByName(node.getName())
                    : graph.getNodeByAddress(node.getAddress());
            if ("prefer_local".equals(mergePolicy) && existing != null) {
                addressToId.put(node.getAddress(), existing.getId());
                endpointToId.put(graphEndpointKey(node.getAddress(), node.getName()), existing.getId());
                if (node.getName() != null) {
                    nameToId.put(node.getName(), existing.getId());
                }
                continue;
            }

            KnowledgeNode localNode = node.getId() != null
                    ? new KnowledgeNode(node.getId(), nodeType, programHash)
                    : new KnowledgeNode(nodeType, programHash);
            if (existing != null) {
                localNode.setId(existing.getId());
            }

            localNode.setAddress(node.getAddress());
            localNode.setName(node.getName());
            localNode.setSignature(node.getSignature());

            Map<String, Object> props = node.getProperties();
            String decompiledCode = props != null ? (String) props.get("decompiled_code") : null;
            if (decompiledCode == null && props != null) {
                decompiledCode = (String) props.get("raw_content");
            }
            if (decompiledCode == null && props != null) {
                decompiledCode = (String) props.get("raw_code");
            }
            String disassembly = props != null ? (String) props.get("disassembly") : null;
            String summary = node.getSummary();
            if (summary == null && props != null) {
                summary = (String) props.get("llm_summary");
            }

            localNode.setDecompiledCode(decompiledCode);
            localNode.setDisassembly(disassembly);
            localNode.setRawContent(decompiledCode);
            localNode.setLlmSummary(summary);
            localNode.setConfidence((float) getDoubleProperty(props, "confidence", 0.0));
            localNode.setSecurityFlags(getListProperty(props, "security_flags"));
            localNode.setNetworkAPIs(getListProperty(props, "network_apis"));
            localNode.setFileIOAPIs(getListProperty(props, "file_io_apis"));
            localNode.setIPAddresses(getListProperty(props, "ip_addresses"));
            localNode.setURLs(getListProperty(props, "urls"));
            localNode.setFilePaths(getListProperty(props, "file_paths"));
            localNode.setDomains(getListProperty(props, "domains"));
            localNode.setRegistryKeys(getListProperty(props, "registry_keys"));
            if (props != null) {
                localNode.setRiskLevel((String) props.get("risk_level"));
                localNode.setCategory((String) props.get("category"));
                localNode.setActivityProfile((String) props.get("activity_profile"));
                Object depth = props.get("analysis_depth");
                if (depth instanceof Number) {
                    localNode.setAnalysisDepth(((Number) depth).intValue());
                }
                Object isStale = props.get("is_stale");
                if (isStale instanceof Boolean) {
                    localNode.setStale((Boolean) isStale);
                }
                Object userEdited = props.get("user_edited");
                if (userEdited instanceof Boolean) {
                    localNode.setUserEdited((Boolean) userEdited);
                }
            }

            graph.upsertNode(localNode);
            addressToId.put(node.getAddress(), localNode.getId());
            endpointToId.put(graphEndpointKey(node.getAddress(), node.getName()), localNode.getId());
            if (node.getName() != null) {
                nameToId.put(node.getName(), localNode.getId());
            }
        }

        Gson gson = new Gson();
        for (GraphEdge edge : export.getEdges()) {
            String sourceId = endpointToId.get(graphEndpointKey(edge.getSourceAddress(), edge.getSourceName()));
            if (sourceId == null) {
                sourceId = addressToId.get(edge.getSourceAddress());
            }
            if (sourceId == null && edge.getSourceAddress() == 0 && edge.getSourceName() != null) {
                sourceId = nameToId.get(edge.getSourceName());
            }

            String targetId = endpointToId.get(graphEndpointKey(edge.getTargetAddress(), edge.getTargetName()));
            if (targetId == null) {
                targetId = addressToId.get(edge.getTargetAddress());
            }
            if (targetId == null && edge.getTargetAddress() == 0 && edge.getTargetName() != null) {
                targetId = nameToId.get(edge.getTargetName());
            }
            if (sourceId == null || targetId == null) {
                continue;
            }
            EdgeType edgeType = EdgeType.fromString(edge.getEdgeType());
            if (edgeType == null) {
                edgeType = EdgeType.CALLS;
            }
            Map<String, Object> props = edge.getProperties();
            double weight = getDoubleProperty(props, "weight", 1.0);
            String metadata = props != null ? gson.toJson(props) : null;
            graph.addEdge(sourceId, targetId, edgeType, weight, metadata);
        }
    }

    private String graphEndpointKey(long address, String name) {
        return "addr:" + address + "|name:" + (name != null ? name : "");
    }

    private boolean applyVariableSymbol(Function func,
            ghidrassist.services.symgraph.SymGraphModels.Symbol remoteSymbol) {
        if (remoteSymbol == null || remoteSymbol.getName() == null) {
            return false;
        }

        Map<String, Object> metadata = remoteSymbol.getMetadata();
        if (metadata == null) {
            return false;
        }

        String storageClass = (String) metadata.get("storage_class");
        String targetName = remoteSymbol.getName();

        try {
            if ("parameter".equals(storageClass)) {
                Object paramIdxObj = metadata.get("parameter_index");
                if (paramIdxObj != null) {
                    int paramIdx = ((Number) paramIdxObj).intValue();
                    ghidra.program.model.listing.Parameter[] params = func.getParameters();
                    if (paramIdx < params.length) {
                        params[paramIdx].setName(targetName,
                            ghidra.program.model.symbol.SourceType.USER_DEFINED);
                        return true;
                    }
                }
            } else if ("stack".equals(storageClass)) {
                Object stackOffsetObj = metadata.get("stack_offset");
                if (stackOffsetObj != null) {
                    int stackOffset = ((Number) stackOffsetObj).intValue();
                    for (ghidra.program.model.listing.Variable var : func.getLocalVariables()) {
                        if (var.isStackVariable()) {
                            try {
                                if (var.getStackOffset() == stackOffset) {
                                    var.setName(targetName,
                                        ghidra.program.model.symbol.SourceType.USER_DEFINED);
                                    return true;
                                }
                            } catch (UnsupportedOperationException e) {
                                // Not a simple stack var
                            }
                        }
                    }
                }
            } else if ("register".equals(storageClass)) {
                String regName = (String) metadata.get("register");
                if (regName != null) {
                    for (ghidra.program.model.listing.Variable var : func.getLocalVariables()) {
                        if (var.isRegisterVariable()) {
                            ghidra.program.model.lang.Register reg = var.getRegister();
                            if (reg != null && regName.equals(reg.getName())) {
                                var.setName(targetName,
                                    ghidra.program.model.symbol.SourceType.USER_DEFINED);
                                return true;
                            }
                        }
                    }
                }
            }
        } catch (Exception e) {
            Msg.error(this, "Error applying variable: " + e.getMessage());
        }

        return false;
    }

    public void handleSymGraphApplySelected(List<ConflictEntry> selectedConflicts) {
        symGraphController.handleApplySelected(selectedConflicts);
    }

    public void handleSymGraphApplyAllNew() {
        symGraphController.handleApplyAllNew();
    }

    public void cancelSymGraphApply() {
        symGraphController.cancelApply();
    }

    public void cancelSymGraphPull() {
        symGraphController.cancelPull();
    }

    public void updateSymGraphBinaryInfo() {
        symGraphController.updateBinaryInfo();
    }




    // ==== Cleanup ====


    public void dispose() {
        codeAnalysisService.close();
        analysisDataService.close();
        feedbackService.close();

        // Shutdown safety scheduler
        if (safetyScheduler != null) {
            safetyScheduler.shutdown();
        }
    }
}
