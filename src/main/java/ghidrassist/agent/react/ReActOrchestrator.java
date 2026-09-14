package ghidrassist.agent.react;

import ghidrassist.AnalysisDB;
import ghidrassist.GhidrAssistPlugin;
import ghidrassist.LlmApi;
import ghidrassist.apiprovider.APIProviderConfig;
import ghidrassist.apiprovider.ToolChoiceMode;
import ghidrassist.mcp2.tools.MCPTool;
import ghidrassist.mcp2.tools.MCPToolManager;
import ghidrassist.context.ContextWindowListener;
import ghidrassist.tools.approval.ToolApprovalService;
import ghidrassist.tools.api.Tool;
import ghidrassist.tools.api.ToolExecutionObserver;
import ghidrassist.tools.native_.DocumentToolProvider;
import ghidrassist.tools.native_.NativeToolManager;
import ghidrassist.tools.registry.ToolRegistry;

import ghidra.util.Msg;

import java.time.Duration;
import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Collectors;

/**
 * ReAct orchestrator that adds Think-Act-Observe structure on top of
 * the existing ConversationalToolHandler.
 *
 * Key features:
 * - Todo list management for tracking investigation progress
 * - Findings accumulation with relevance scoring
 * - Context window management with token-based thresholds
 * - Unified conversation history with chunked iterations
 * - Structured prompts with todos and findings
 * - Reflection-based plan adaptation
 * - Dynamic iteration budget extension
 *
 * Enhanced for BinAssist feature parity.
 */
public class ReActOrchestrator {

    private static final int MAX_LLM_FUNCTION_TOOLS = 120;

    // Configuration
    private int maxIterations;  // Now mutable for dynamic extension
    private final int baseMaxIterations;  // Original limit for tracking
    private final int contextSummaryThreshold;
    private final int maxToolRounds;  // Maximum tool calls per iteration

    // Dependencies
    private final LlmApi llmApi;
    private final MCPToolManager mcpToolManager;
    private final ToolRegistry toolRegistry;
    private final GhidrAssistPlugin plugin;
    private NativeToolManager nativeToolManager;

    // Conversation history manager (optional - for persistence)
    private ConversationHistoryManager historyManager;

    // Cancellation support
    private final AtomicBoolean cancelled = new AtomicBoolean(false);
    private final Object analysisStateLock = new Object();
    private volatile CompletableFuture<ReActResult> activeResultFuture;
    private volatile Instant activeStartTime;
    private volatile FindingsCache activeFindings;

    public ReActOrchestrator(APIProviderConfig providerConfig, GhidrAssistPlugin plugin) {
        this(providerConfig, plugin, 18, 8000, 10);
    }

    public ReActOrchestrator(
        APIProviderConfig providerConfig,
        GhidrAssistPlugin plugin,
        int maxIterations,
        int contextSummaryThreshold
    ) {
        this(providerConfig, plugin, maxIterations, contextSummaryThreshold, 10);
    }

    public ReActOrchestrator(
        APIProviderConfig providerConfig,
        GhidrAssistPlugin plugin,
        int maxIterations,
        int contextSummaryThreshold,
        int maxToolRounds
    ) {
        this.plugin = plugin;
        this.maxIterations = maxIterations;
        this.baseMaxIterations = maxIterations;  // Store original limit
        this.contextSummaryThreshold = contextSummaryThreshold;
        this.maxToolRounds = maxToolRounds > 0 ? maxToolRounds : 10;  // Default to 10 if invalid
        this.llmApi = new LlmApi(providerConfig, plugin);
        this.mcpToolManager = MCPToolManager.getInstance();

        // Apply saved reasoning config
        ghidra.program.model.listing.Program currentProgram = plugin.getCurrentProgram();
        if (currentProgram != null) {
            try {
                AnalysisDB analysisDB = new AnalysisDB();
                String programHash = currentProgram.getExecutableSHA256();
                String savedEffort = analysisDB.getReasoningEffort(programHash);
                if (savedEffort != null && !savedEffort.equalsIgnoreCase("none")) {
                    ghidrassist.apiprovider.ReasoningConfig reasoningConfig =
                            ghidrassist.apiprovider.ReasoningConfig.fromString(savedEffort);
                    llmApi.setReasoningConfig(reasoningConfig);
                }
            } catch (Exception e) {
                // Continue without reasoning config if loading fails
            }
        }

        // Initialize unified ToolRegistry with both native and MCP tools
        this.toolRegistry = initializeToolRegistry();
    }

    /**
     * Initialize the unified ToolRegistry with all tool providers.
     */
    private ToolRegistry initializeToolRegistry() {
        ToolRegistry registry = new ToolRegistry();

        try {
            // Register native tools (semantic, actions)
            AnalysisDB analysisDB = new AnalysisDB();
            this.nativeToolManager = new NativeToolManager(analysisDB);
            registry.registerProvider(nativeToolManager);

            // Register MCP tools
            registry.registerProvider(mcpToolManager);

            // Set program context for tools that need it
            ghidra.program.model.listing.Program currentProgram = plugin.getCurrentProgram();
            if (currentProgram != null) {
                registry.setContext(currentProgram);
            }

            Msg.info(this, registry.getSummary());

        } catch (Exception e) {
            Msg.error(this, "Failed to initialize ToolRegistry: " + e.getMessage(), e);
        }

        return registry;
    }

    /**
     * Set the handler for document chat creation.
     *
     * @param handler The handler to use for creating document chats
     */
    public void setDocumentChatHandler(DocumentToolProvider.DocumentChatHandler handler) {
        if (nativeToolManager != null) {
            nativeToolManager.setDocumentChatHandler(handler);
        }
    }

    /**
     * Update program context for all tools when program changes.
     */
    public void updateProgramContext(ghidra.program.model.listing.Program program) {
        if (toolRegistry != null) {
            toolRegistry.setContext(program);
        }
    }

    public void setToolExecutionObserver(ToolExecutionObserver observer) {
        if (toolRegistry != null) {
            toolRegistry.setExecutionObserver(observer);
        }
    }

    public void setToolApprovalService(ToolApprovalService approvalService) {
        if (toolRegistry != null) {
            toolRegistry.setApprovalService(approvalService);
        }
    }

    public void setActiveSessionId(int sessionId) {
        if (toolRegistry != null) {
            toolRegistry.setActiveSessionSupplier(() -> sessionId);
        }
    }

    public void setProgramHashSupplier(java.util.function.Supplier<String> programHashSupplier) {
        if (toolRegistry != null) {
            toolRegistry.setProgramHashSupplier(programHashSupplier);
        }
    }

    public void setContextWindowListener(ContextWindowListener listener) {
        llmApi.setContextWindowListener(listener);
    }

    /**
     * Get all tools from ToolRegistry in LLM function calling format.
     */
    private List<Map<String, Object>> getToolsAsFunction(String queryContext) {
        if (toolRegistry == null) {
            return List.of();
        }

        return toolRegistry.getToolsAsFunction(queryContext, MAX_LLM_FUNCTION_TOOLS);
    }

    /**
     * Convert a Tool to OpenAI function calling schema format.
     */
    private Map<String, Object> toolToFunctionSchema(Tool tool) {
        Map<String, Object> function = new HashMap<>();
        function.put("type", "function");

        Map<String, Object> functionDef = new HashMap<>();
        functionDef.put("name", tool.getName());
        functionDef.put("description", tool.getDescription());

        if (tool.getInputSchema() != null) {
            // Convert JsonObject to Map for compatibility
            functionDef.put("parameters", jsonObjectToMap(tool.getInputSchema()));
        } else {
            // Empty parameters schema
            Map<String, Object> emptyParams = new HashMap<>();
            emptyParams.put("type", "object");
            emptyParams.put("properties", new HashMap<>());
            functionDef.put("parameters", emptyParams);
        }

        function.put("function", functionDef);
        return function;
    }

    /**
     * Convert JsonObject to Map for function schema compatibility.
     */
    private Map<String, Object> jsonObjectToMap(com.google.gson.JsonObject jsonObject) {
        Map<String, Object> map = new HashMap<>();
        for (String key : jsonObject.keySet()) {
            Object value = jsonElementToObject(jsonObject.get(key));
            map.put(key, value);
        }
        return map;
    }

    /**
     * Convert JsonElement to Java object.
     */
    private Object jsonElementToObject(com.google.gson.JsonElement element) {
        if (element.isJsonPrimitive()) {
            if (element.getAsJsonPrimitive().isString()) {
                return element.getAsString();
            } else if (element.getAsJsonPrimitive().isNumber()) {
                return element.getAsNumber();
            } else if (element.getAsJsonPrimitive().isBoolean()) {
                return element.getAsBoolean();
            }
        } else if (element.isJsonObject()) {
            return jsonObjectToMap(element.getAsJsonObject());
        } else if (element.isJsonArray()) {
            com.google.gson.JsonArray array = element.getAsJsonArray();
            java.util.ArrayList<Object> list = new java.util.ArrayList<>();
            for (int i = 0; i < array.size(); i++) {
                list.add(jsonElementToObject(array.get(i)));
            }
            return list;
        }
        return null;
    }

    /**
     * Analyze a query using ReAct pattern with conversational tool calling.
     */
    public CompletableFuture<ReActResult> analyze(
        String query,
        String initialContext,
        String sessionId,
        ReActProgressHandler handler
    ) {
        return analyze(query, initialContext, sessionId, handler, null);
    }

    public CompletableFuture<ReActResult> analyze(
        String query,
        String initialContext,
        String sessionId,
        ReActProgressHandler handler,
        String approvedPlan
    ) {
        CompletableFuture<ReActResult> resultFuture = new CompletableFuture<>();
        resultFuture.whenComplete((result, error) -> clearActiveAnalysis(resultFuture));
        Instant startTime = Instant.now();
        cancelled.set(false);

        try {
            // Initialize components
            TodoListManager todoManager = new TodoListManager(query);
            FindingsCache findings = new FindingsCache();
            ContextSummarizer summarizer = new ContextSummarizer(contextSummaryThreshold);
            registerActiveAnalysis(resultFuture, startTime, findings);

            handler.onStart(query);

            if (cancelled.get() || !handler.shouldContinue()) {
                completeWithCancellation(resultFuture, findings, startTime, handler);
                return resultFuture;
            }

            if (approvedPlan != null && !approvedPlan.isBlank()) {
                todoManager.initializeFromLLMResponse(approvedPlan);
                handler.onTodosUpdated(
                    todoManager.formatForPrompt(),
                    todoManager.getAllTodos(),
                    todoManager.toCompactString());
                List<Map<String, Object>> tools = getToolsAsFunction();
                AtomicInteger iteration = new AtomicInteger(0);
                AtomicInteger toolCallCount = new AtomicInteger(0);
                runReActIteration(
                    query,
                    initialContext,
                    todoManager,
                    findings,
                    summarizer,
                    tools,
                    iteration,
                    toolCallCount,
                    handler,
                    startTime,
                    resultFuture
                );
                return resultFuture;
            }

            // First, ask LLM to propose investigation steps
            Msg.info(this, "Asking LLM to plan investigation steps...");
            String planningPrompt = ReActPrompts.getPlanningPrompt(query, initialContext);

            llmApi.sendRequestAsync(planningPrompt, new LlmApi.LlmResponseHandler() {
                @Override
                public void onStart() {
                }

                @Override
                public void onUpdate(String partialResponse) {
                }

                @Override
                public void onComplete(String fullResponse) {
                    if (resultFuture.isDone()) {
                        return;
                    }
                    if (cancelled.get() || !handler.shouldContinue()) {
                        completeWithCancellation(resultFuture, findings, startTime, handler);
                        return;
                    }

                    try {
                        todoManager.initializeFromLLMResponse(fullResponse);
                        Msg.info(ReActOrchestrator.this, "Investigation plan created with " +
                            todoManager.getAllTodos().size() + " steps");

                        handler.onTodosUpdated(
                            todoManager.formatForPrompt(),
                            todoManager.getAllTodos(),
                            todoManager.toCompactString());

                // Get available tools from all providers via ToolRegistry
                List<Map<String, Object>> tools = getToolsAsFunction(query);
                if (tools.isEmpty()) {
                    Msg.warn(this, "No tools available - analysis may be limited");
                } else {
                    Msg.info(this, "Loaded " + tools.size() + " tools from ToolRegistry");
                }

                        // Track iteration count
                        AtomicInteger iteration = new AtomicInteger(0);
                        AtomicInteger toolCallCount = new AtomicInteger(0);

                        // Main ReAct loop
                        runReActIteration(
                            query,
                            initialContext,
                            todoManager,
                            findings,
                            summarizer,
                            tools,
                            iteration,
                            toolCallCount,
                            handler,
                            startTime,
                            resultFuture
                        );
                    } catch (Exception e) {
                        Msg.error(ReActOrchestrator.this,
                            "ReAct planning continuation failed: " + e.getMessage(), e);
                        completeWithError(resultFuture, e, findings, startTime, handler);
                    }
                }

                @Override
                public void onError(Throwable error) {
                    completeWithError(resultFuture, error, findings, startTime, handler);
                }

                @Override
                public boolean shouldContinue() {
                    return !resultFuture.isDone() && !cancelled.get() && handler.shouldContinue();
                }
            });
        } catch (Exception e) {
            Msg.error(this, "ReAct analysis error: " + e.getMessage(), e);
            completeWithError(resultFuture, e, new FindingsCache(), startTime, handler);
        }

        return resultFuture;
    }

    /**
     * Run one iteration of the ReAct loop.
     */
    private void runReActIteration(
        String objective,
        String initialContext,
        TodoListManager todoManager,
        FindingsCache findings,
        ContextSummarizer summarizer,
        List<Map<String, Object>> tools,
        AtomicInteger iteration,
        AtomicInteger toolCallCount,
        ReActProgressHandler handler,
        Instant startTime,
        CompletableFuture<ReActResult> resultFuture
    ) {
        // Check termination conditions
        if (cancelled.get() || !handler.shouldContinue()) {
            completeWithCancellation(resultFuture, findings, startTime, handler);
            return;
        }

        int currentIteration = iteration.incrementAndGet();

        if (currentIteration > maxIterations) {
            // Max iterations reached - synthesize answer
            synthesizeFinalAnswer(objective, todoManager, findings, tools, handler, startTime, resultFuture, currentIteration, toolCallCount.get(), ReActResult.Status.MAX_ITERATIONS);
            return;
        }

        if (todoManager.allComplete()) {
            // All todos done - synthesize answer
            synthesizeFinalAnswer(objective, todoManager, findings, tools, handler, startTime, resultFuture, currentIteration, toolCallCount.get(), ReActResult.Status.SUCCESS);
            return;
        }

        Msg.info(this, String.format("ReAct iteration %d/%d", currentIteration, maxIterations));

        // Mark next pending todo as in progress
        TodoListManager.Todo nextTodo = todoManager.getNextPending();
        if (nextTodo != null) {
            todoManager.setInProgress(nextTodo.getTask());
            handler.onIterationStarted(currentIteration, nextTodo.getTask());
            handler.onTodosUpdated(
                todoManager.formatForPrompt(),
                todoManager.getAllTodos(),
                todoManager.toCompactString());
        } else {
            handler.onIterationStarted(currentIteration, null);
        }

        // Build investigation prompt
        // Use enhanced findings format: top 50 findings, 500 chars each (BinAssist parity)
        String prompt = ReActPrompts.buildInvestigationPrompt(
            objective,
            currentIteration == 1 ? initialContext : null,  // Only include context on first iteration
            todoManager.formatForPrompt(),
            findings.formatForPrompt(50, 500),  // Top 50, max 500 chars per finding
            currentIteration
        );

        // Add warning if approaching limit
        if (maxIterations - currentIteration <= 3) {
            prompt += ReActPrompts.getIterationLimitWarning(maxIterations - currentIteration);
            handler.onIterationWarning(maxIterations - currentIteration);
        }

        // Create response handler for this iteration
        LlmApi.LlmResponseHandler iterationHandler = new LlmApi.LlmResponseHandler() {
            private final StringBuilder responseBuffer = new StringBuilder();
            private final StringBuilder displayBuffer = new StringBuilder();
            private boolean hasCalledTools = false;
            private boolean toolsExecutedThisRound = false;

            @Override
            public void onStart() {
                responseBuffer.setLength(0);
                displayBuffer.setLength(0);
            }

            @Override
            public void onUpdate(String partialResponse) {
                // Forward ALL conversational updates to the UI immediately
                if (partialResponse != null && !partialResponse.isEmpty()) {
                    responseBuffer.append(partialResponse);
                    displayBuffer.append(partialResponse);

                    // Pass through to progress handler for real-time display
                    // This shows tool execution, assistant thinking, etc.
                    handler.onThought(displayBuffer.toString(), currentIteration);
                }
            }

            @Override
            public void onToolsExecuted(int toolCount) {
                toolsExecutedThisRound = true;
                hasCalledTools = true;
                toolCallCount.addAndGet(toolCount);
            }

            @Override
            public void onComplete(String fullResponse) {
                if (resultFuture.isDone()) {
                    return;
                }
                if (cancelled.get() || !handler.shouldContinue()) {
                    completeWithCancellation(resultFuture, findings, startTime, handler);
                    return;
                }

                // Defense-in-depth: if fullResponse is just a status message (e.g. from
                // max tool rounds), use the responseBuffer which accumulated all streamed content
                String contentForFindings = fullResponse;
                if (fullResponse == null || fullResponse.length() < 100 ||
                    fullResponse.startsWith("Maximum tool")) {
                    String buffered = responseBuffer.toString();
                    if (!buffered.isEmpty()) {
                        contentForFindings = buffered;
                    }
                }

                // Extract findings from the response (keyword-based, for backwards compatibility)
                findings.extractFromToolOutput("llm_response", contentForFindings);

                // Store the iteration summary (LLM's final analysis) for synthesis
                findings.addIterationSummary(contentForFindings);

                // Only mark todo complete if tools were actually executed this round
                if (toolsExecutedThisRound) {
                    updateTodosFromResponse(todoManager, fullResponse);
                } else {
                    Msg.info(ReActOrchestrator.this, "No tools executed this round - not marking todo complete");
                }
                handler.onTodosUpdated(
                    todoManager.formatForPrompt(),
                    todoManager.getAllTodos(),
                    todoManager.toCompactString());

                // Check if we should continue or finish
                if (todoManager.allComplete() || !hasCalledTools) {
                    // Either done or no more tools to call - synthesize
                    synthesizeFinalAnswer(objective, todoManager, findings, tools, handler, startTime, resultFuture, currentIteration, toolCallCount.get(), ReActResult.Status.SUCCESS);
                } else {
                    // Perform self-reflection to determine if we should continue
                    performSelfReflection(
                        objective,
                        initialContext,
                        todoManager,
                        findings,
                        summarizer,
                        tools,
                        iteration,
                        toolCallCount,
                        handler,
                        startTime,
                        resultFuture,
                        currentIteration
                    );
                }
            }

            @Override
            public void onError(Throwable error) {
                if (resultFuture.isDone()) {
                    return;
                }

                // Salvage any findings accumulated from tool calls before the error
                String buffered = responseBuffer.toString();
                if (!buffered.isEmpty()) {
                    findings.extractFromToolOutput("llm_response", buffered);
                    findings.addIterationSummary(buffered);
                }

                completeWithError(resultFuture, error, findings, startTime, handler);
            }

            @Override
            public boolean shouldContinue() {
                return !resultFuture.isDone() && handler.shouldContinue() && !cancelled.get();
            }
        };

        // Call the conversational tool handler
        llmApi.sendConversationalToolRequest(prompt, tools, iterationHandler, maxToolRounds,
            toolRegistry, ToolChoiceMode.REQUIRED_INITIAL);
    }

    /**
     * Synthesize final answer from accumulated findings.
     */
    private void synthesizeFinalAnswer(
        String objective,
        TodoListManager todoManager,
        FindingsCache findings,
        List<Map<String, Object>> tools,
        ReActProgressHandler handler,
        Instant startTime,
        CompletableFuture<ReActResult> resultFuture,
        int iterationCount,
        int toolCallCount,
        ReActResult.Status completionStatus
    ) {
        String synthesisPrompt = ReActPrompts.getSynthesisPrompt(
            objective,
            findings.formatDetailed(),
            todoManager.getCompletedSummary(),
            findings.formatIterationSummaries()
        );

        // Get final answer without tool calling
        llmApi.sendRequestAsync(synthesisPrompt, new LlmApi.LlmResponseHandler() {
            private final StringBuilder answer = new StringBuilder();

            @Override
            public void onStart() {
                answer.setLength(0);
            }

            @Override
            public void onUpdate(String partialResponse) {
                if (resultFuture.isDone() || cancelled.get()) {
                    return;
                }
                answer.append(partialResponse);
                // Stream synthesis to UI
                handler.onSynthesisChunk(partialResponse);
            }

            @Override
            public void onComplete(String fullResponse) {
                if (resultFuture.isDone()) {
                    return;
                }
                if (cancelled.get() || !handler.shouldContinue()) {
                    completeWithCancellation(resultFuture, findings, startTime, handler);
                    return;
                }

                // Build result with the provided completion status
                ReActResult result = new ReActResult.Builder()
                    .status(completionStatus)
                    .answer(fullResponse)
                    .findings(findings.getAllFindings().stream()
                        .map(f -> f.getFact())
                        .toList())
                    .iterationSummaries(findings.getIterationSummaries())
                    .iterationCount(iterationCount)
                    .toolCallCount(toolCallCount)
                    .duration(Duration.between(startTime, Instant.now()))
                    .build();

                completeWithResult(resultFuture, result, handler);
            }

            @Override
            public void onError(Throwable error) {
                completeWithError(resultFuture, error, findings, startTime, handler);
            }

            @Override
            public boolean shouldContinue() {
                return !resultFuture.isDone() && !cancelled.get() && handler.shouldContinue();
            }
        });
    }

    /**
     * Perform self-reflection to determine if investigation should continue.
     */
    private void performSelfReflection(
        String objective,
        String initialContext,
        TodoListManager todoManager,
        FindingsCache findings,
        ContextSummarizer summarizer,
        List<Map<String, Object>> tools,
        AtomicInteger iteration,
        AtomicInteger toolCallCount,
        ReActProgressHandler handler,
        Instant startTime,
        CompletableFuture<ReActResult> resultFuture,
        int currentIteration
    ) {
        String reflectionPrompt = ReActPrompts.getReflectionPrompt(
            objective,
            findings.formatForPrompt(),
            todoManager.formatForPrompt()
        );

        // Ask the LLM to reflect
        CompletableFuture<String> reflectionFuture = new CompletableFuture<>();
        llmApi.sendRequestAsync(reflectionPrompt, new LlmApi.LlmResponseHandler() {
            private final StringBuilder reflection = new StringBuilder();

            @Override
            public void onStart() {
                reflection.setLength(0);
            }

            @Override
            public void onUpdate(String partialResponse) {
                reflection.append(partialResponse);
            }

            @Override
            public void onComplete(String fullResponse) {
                reflectionFuture.complete(fullResponse);
            }

            @Override
            public void onError(Throwable error) {
                // On error, default to continuing
                Msg.warn(ReActOrchestrator.this, "Reflection failed, continuing investigation: " + error.getMessage());
                reflectionFuture.complete("CONTINUE: Reflection error, continuing investigation");
            }

            @Override
            public boolean shouldContinue() {
                return !resultFuture.isDone() && !cancelled.get() && handler.shouldContinue();
            }
        });

        // Wait for reflection and decide next action
        reflectionFuture.thenAccept(reflectionResponse -> {
            if (resultFuture.isDone()) {
                return;
            }
            if (cancelled.get() || !handler.shouldContinue()) {
                completeWithCancellation(resultFuture, findings, startTime, handler);
                return;
            }

            String trimmedResponse = reflectionResponse.trim();

            // Parse structured reflection response for plan updates
            ReflectionParsed parsed = parseReflectionResponse(trimmedResponse);

            // Apply plan updates if present (ADD/REMOVE tasks)
            boolean planChanged = false;
            if (!parsed.tasksToAdd.isEmpty() || !parsed.tasksToRemove.isEmpty()) {
                planChanged = todoManager.updateFromReflection(parsed.tasksToAdd, parsed.tasksToRemove);

                if (planChanged) {
                    Msg.info(this, String.format(
                        "Reflection updated plan: +%d tasks, -%d tasks",
                        parsed.tasksToAdd.size(), parsed.tasksToRemove.size()
                    ));
                    handler.onTodosUpdated(
                        todoManager.formatForPrompt(),
                        todoManager.getAllTodos(),
                        todoManager.toCompactString());

                    // Dynamic iteration budget extension (BinAssist parity)
                    if (!parsed.tasksToAdd.isEmpty()) {
                        int extensionAmount = parsed.tasksToAdd.size();
                        maxIterations += extensionAmount;
                        Msg.info(this, String.format(
                            "Extended iteration budget by %d (new limit: %d)",
                            extensionAmount, maxIterations
                        ));
                        handler.onFinding(String.format(
                            "⚡ Extended investigation budget: +%d iterations (new limit: %d)",
                            extensionAmount, maxIterations
                        ));
                    }
                }
            }

            // Determine if ready to synthesize
            boolean shouldSynthesize = "READY".equals(parsed.decision);

            if (shouldSynthesize) {
                // Log reflection and decision
                handler.onFinding("Self-Reflection: " + parsed.assessment);
                handler.onFinding("Decision: READY - Sufficient information gathered, synthesizing final answer");
                synthesizeFinalAnswer(objective, todoManager, findings, tools, handler, startTime, resultFuture, currentIteration, toolCallCount.get(), ReActResult.Status.SUCCESS);
            } else {
                // Log reflection and decision
                handler.onFinding("Self-Reflection: " + parsed.assessment);
                handler.onFinding("Decision: CONTINUE - " + parsed.reason);
                // Continue to next iteration
                runReActIteration(
                    objective,
                    initialContext,
                    todoManager,
                    findings,
                    summarizer,
                    tools,
                    iteration,
                    toolCallCount,
                    handler,
                    startTime,
                    resultFuture
                );
            }
        }).exceptionally(error -> {
            if (resultFuture.isDone()) {
                return null;
            }
            if (cancelled.get() || !handler.shouldContinue()) {
                completeWithCancellation(resultFuture, findings, startTime, handler);
                return null;
            }
            Msg.error(this, "Reflection handling failed: " + error.getMessage(), error);
            handler.onThought("⚠️ **Error in reflection**: " + error.getMessage() + ". Continuing investigation...\n\n", currentIteration);
            // On error, continue investigation
            runReActIteration(
                objective,
                initialContext,
                todoManager,
                findings,
                summarizer,
                tools,
                iteration,
                toolCallCount,
                handler,
                startTime,
                resultFuture
            );
            return null;
        });
    }

    /**
     * Extract tool name from conversational handler update.
     */
    private String extractToolName(String message) {
        // ConversationalToolHandler formats as "🔧 Calling tool: <name>"
        if (message.contains("Calling tool:")) {
            int start = message.indexOf("Calling tool:") + 13;
            int end = message.indexOf("\n", start);
            if (end == -1) end = message.length();
            return message.substring(start, end).trim();
        }
        return null;
    }

    /**
     * Update todos based on iteration completion.
     * Marks the current in-progress todo as complete after an iteration.
     */
    private void updateTodosFromResponse(TodoListManager todoManager, String response) {
        // After each iteration with tool calls, mark the current in-progress todo as complete
        // The iteration has gathered information, so we consider the step done
        for (TodoListManager.Todo todo : todoManager.getAllTodos()) {
            if (todo.getStatus() == TodoListManager.TodoStatus.IN_PROGRESS) {
                // Mark complete - the investigation step has been executed
                todoManager.completeTodo(todo.getTask(), "Investigation step completed");
                Msg.info(this, "Completed todo: " + todo.getTask());
                break;  // Only one should be in progress at a time
            }
        }
    }

    /**
     * Parse structured reflection response.
     * Expected format:
     * **Assessment:** ...
     * **Plan Updates:**
     * - ADD: task (or "None")
     * - REMOVE: task (or "None")
     * **Decision:** READY or CONTINUE
     * **Reason:** ...
     */
    private ReflectionParsed parseReflectionResponse(String response) {
        ReflectionParsed parsed = new ReflectionParsed();

        String[] lines = response.split("\n");
        boolean inPlanUpdates = false;

        for (String line : lines) {
            line = line.trim();

            // Parse Assessment
            if (line.startsWith("**Assessment:**")) {
                parsed.assessment = line.substring("**Assessment:**".length()).trim();
            }
            // Parse Plan Updates section
            else if (line.startsWith("**Plan Updates:**")) {
                inPlanUpdates = true;
            }
            // Parse Decision
            else if (line.startsWith("**Decision:**")) {
                inPlanUpdates = false;
                String decision = line.substring("**Decision:**".length()).trim().toUpperCase();
                // Extract READY or CONTINUE
                if (decision.contains("READY") && !decision.contains("NOT READY")) {
                    parsed.decision = "READY";
                } else {
                    parsed.decision = "CONTINUE";
                }
            }
            // Parse Reason
            else if (line.startsWith("**Reason:**")) {
                parsed.reason = line.substring("**Reason:**".length()).trim();
            }
            // Parse ADD/REMOVE within Plan Updates
            else if (inPlanUpdates) {
                if (line.startsWith("- ADD:") || line.startsWith("-ADD:")) {
                    String task = line.replaceFirst("^-\\s*ADD:\\s*", "").trim();
                    if (!task.equalsIgnoreCase("None") && !task.isEmpty()) {
                        parsed.tasksToAdd.add(task);
                    }
                } else if (line.startsWith("- REMOVE:") || line.startsWith("-REMOVE:")) {
                    String task = line.replaceFirst("^-\\s*REMOVE:\\s*", "").trim();
                    if (!task.equalsIgnoreCase("None") && !task.isEmpty()) {
                        parsed.tasksToRemove.add(task);
                    }
                }
            }
        }

        // Fallback parsing if structured format not found
        if (parsed.decision == null) {
            String upperResponse = response.toUpperCase();
            if (upperResponse.contains("READY:") || upperResponse.startsWith("READY")) {
                parsed.decision = "READY";
                parsed.assessment = "Ready to synthesize (legacy format)";
            } else {
                parsed.decision = "CONTINUE";
                parsed.assessment = "Continue investigation (legacy format)";
            }
        }

        return parsed;
    }

    private void registerActiveAnalysis(
        CompletableFuture<ReActResult> resultFuture,
        Instant startTime,
        FindingsCache findings
    ) {
        synchronized (analysisStateLock) {
            activeResultFuture = resultFuture;
            activeStartTime = startTime;
            activeFindings = findings;
        }
    }

    private void clearActiveAnalysis(CompletableFuture<ReActResult> resultFuture) {
        synchronized (analysisStateLock) {
            if (activeResultFuture == resultFuture) {
                activeResultFuture = null;
                activeStartTime = null;
                activeFindings = null;
            }
        }
    }

    private void completeWithResult(
        CompletableFuture<ReActResult> resultFuture,
        ReActResult result,
        ReActProgressHandler handler
    ) {
        if (resultFuture.complete(result)) {
            handler.onComplete(result);
        }
    }

    private void completeWithError(
        CompletableFuture<ReActResult> resultFuture,
        Throwable error,
        FindingsCache findings,
        Instant startTime,
        ReActProgressHandler handler
    ) {
        ReActResult result = ReActResult.error(error, findings, Duration.between(startTime, Instant.now()));
        if (resultFuture.complete(result)) {
            handler.onError(error);
            handler.onComplete(result);
        }
    }

    private void completeWithCancellation(
        CompletableFuture<ReActResult> resultFuture,
        FindingsCache findings,
        Instant startTime,
        ReActProgressHandler handler
    ) {
        ReActResult result = ReActResult.cancelled(findings, Duration.between(startTime, Instant.now()));
        if (resultFuture.complete(result)) {
            handler.onComplete(result);
        }
    }

    /**
     * Helper class for parsed reflection response.
     */
    private static class ReflectionParsed {
        String assessment = "";
        List<String> tasksToAdd = new java.util.ArrayList<>();
        List<String> tasksToRemove = new java.util.ArrayList<>();
        String decision = null;  // "READY" or "CONTINUE"
        String reason = "";
    }

    /**
     * Cancel the current analysis.
     */
    public void cancel() {
        cancelled.set(true);
        llmApi.cancelCurrentRequest();

        CompletableFuture<ReActResult> resultFuture = activeResultFuture;
        Instant startTime = activeStartTime;
        FindingsCache findings = activeFindings;
        if (resultFuture != null && startTime != null) {
            ReActResult cancelledResult = ReActResult.cancelled(
                findings,
                Duration.between(startTime, Instant.now())
            );
            resultFuture.complete(cancelledResult);
        }
    }
}
