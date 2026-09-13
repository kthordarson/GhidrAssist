package ghidrassist.core;

import ghidrassist.LlmApi;
import ghidrassist.apiprovider.AnthropicPlatformApiProvider;
import ghidrassist.apiprovider.LMStudioProvider;
import ghidrassist.apiprovider.ChatMessage;
import ghidrassist.apiprovider.OpenAIPlatformApiProvider;
import ghidrassist.apiprovider.ToolChoiceMode;
import ghidrassist.apiprovider.exceptions.RateLimitException;
import ghidrassist.context.ContextWindowManager;
import ghidrassist.context.ContextStatus;
import ghidrassist.tools.api.ToolResult;
import ghidrassist.tools.registry.ToolRegistry;
import ghidra.util.Msg;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CompletableFuture;

/**
 * Handles conversational tool calling with proper finish_reason monitoring.
 * Manages the turn-by-turn conversation flow with the LLM and MCP tool execution.
 */
public class ConversationalToolHandler {

    private final LlmApiClient apiClient;
    private final List<Map<String, Object>> availableFunctions;
    private final ResponseProcessor responseProcessor;
    private final LlmApi.LlmResponseHandler userHandler;
    @SuppressWarnings("unused")  // Reserved for future error handling enhancement
    private final LlmErrorHandler errorHandler;
    private final Runnable onCompletionCallback;
    private final ToolRegistry toolRegistry;
    private final ContextWindowManager contextWindowManager; // nullable - for proper context management
    private final ToolChoiceMode toolChoiceMode;

    private final List<ChatMessage> conversationHistory;
    private final StringBuilder accumulatedAssistantContent = new StringBuilder();
    private volatile boolean isConversationActive = false;
    private volatile boolean isCancelled = false;
    private int rateLimitRetries = 0;
    private int toolCallRound = 0; // Track tool calling rounds within iteration
    private static final int MAX_RATE_LIMIT_BACKOFF_SECONDS = 60;
    private static final int MAX_CONVERSATION_HISTORY = 40; // Safety net message count cap
    private static final int MAX_CONVERSATION_CHARS = 600000; // ~150K tokens at 4 chars/token
    private static final double COMPRESSION_THRESHOLD = 0.75; // Trigger compression at 75% of char limit
    private static final int MIN_RECENT_MESSAGES = 8; // Always keep last 8 messages
    private final int maxToolRounds; // Maximum tool calling rounds per iteration (configurable)

    private static final String SUMMARY_PROMPT = "Summarize the following investigation conversation concisely.\n\n" +
        "Preserve these key elements:\n" +
        "- Important discoveries and findings\n" +
        "- Tools that were used and their significant results\n" +
        "- Current investigation progress and state\n" +
        "- Any identified patterns, vulnerabilities, or issues\n" +
        "- Key addresses, function names, or code references mentioned\n\n" +
        "Previous conversation to summarize:\n%s\n\n" +
        "Provide a concise summary (target: ~500 words) that captures the essential context " +
        "needed to continue this investigation effectively. Focus on facts and findings, not the conversation flow.";

    public ConversationalToolHandler(
            LlmApiClient apiClient,
            List<Map<String, Object>> functions,
            ResponseProcessor responseProcessor,
            LlmApi.LlmResponseHandler userHandler,
            LlmErrorHandler errorHandler,
            Runnable onCompletionCallback,
            int maxToolRounds,
            ToolRegistry toolRegistry) {
        this(apiClient, functions, responseProcessor, userHandler, errorHandler, onCompletionCallback,
            maxToolRounds, toolRegistry, null, ToolChoiceMode.AUTO);
    }

    public ConversationalToolHandler(
            LlmApiClient apiClient,
            List<Map<String, Object>> functions,
            ResponseProcessor responseProcessor,
            LlmApi.LlmResponseHandler userHandler,
            LlmErrorHandler errorHandler,
            Runnable onCompletionCallback,
            int maxToolRounds,
            ToolRegistry toolRegistry,
            ContextWindowManager contextWindowManager) {
        this(apiClient, functions, responseProcessor, userHandler, errorHandler, onCompletionCallback,
            maxToolRounds, toolRegistry, contextWindowManager, ToolChoiceMode.AUTO);
    }

    public ConversationalToolHandler(
            LlmApiClient apiClient,
            List<Map<String, Object>> functions,
            ResponseProcessor responseProcessor,
            LlmApi.LlmResponseHandler userHandler,
            LlmErrorHandler errorHandler,
            Runnable onCompletionCallback,
            int maxToolRounds,
            ToolRegistry toolRegistry,
            ContextWindowManager contextWindowManager,
            ToolChoiceMode toolChoiceMode) {

        this.apiClient = apiClient;
        this.availableFunctions = functions;
        this.responseProcessor = responseProcessor;
        this.userHandler = userHandler;
        this.errorHandler = errorHandler;
        this.onCompletionCallback = onCompletionCallback;
        this.conversationHistory = new ArrayList<>();
        this.maxToolRounds = maxToolRounds > 0 ? maxToolRounds : 10; // Default to 10 if invalid
        this.toolRegistry = toolRegistry;
        this.contextWindowManager = contextWindowManager;
        this.toolChoiceMode = toolChoiceMode != null ? toolChoiceMode : ToolChoiceMode.AUTO;
    }

    /**
     * Start the conversational tool calling session
     */
    public void startConversation(String userPrompt) {
        if (isConversationActive) {
            Msg.warn(this, "Conversation already active, ignoring new request");
            return;
        }

        // Validate prompt is not empty - this can happen on first load with stale state
        if (userPrompt == null || userPrompt.trim().isEmpty()) {
            Msg.warn(this, "Empty prompt received, cannot start conversation");
            userHandler.onError(new IllegalArgumentException(
                "Cannot process empty query. Please try again."));
            if (onCompletionCallback != null) {
                onCompletionCallback.run();
            }
            return;
        }

        isConversationActive = true;
        isCancelled = false; // Reset cancellation flag
        conversationHistory.clear();
        accumulatedAssistantContent.setLength(0); // Reset content accumulator
        rateLimitRetries = 0; // Reset retry counter
        toolCallRound = 0; // Reset tool call round counter

        // Add initial user message
        conversationHistory.addAll(apiClient.createFunctionMessages(userPrompt, toolChoiceMode));

        // Start the conversation loop
        userHandler.onStart();

        continueConversation();
    }

    /**
     * Start the conversational tool calling session with existing history.
     * This preserves thinking content, tool calls, and other metadata from previous turns.
     *
     * @param existingHistory List of ChatMessages from previous conversation (with thinking data)
     * @param newUserPrompt The new user message to add
     */
    public void startConversationWithHistory(List<ChatMessage> existingHistory, String newUserPrompt) {
        if (isConversationActive) {
            Msg.warn(this, "Conversation already active, ignoring new request");
            return;
        }

        // Validate prompt is not empty
        if (newUserPrompt == null || newUserPrompt.trim().isEmpty()) {
            Msg.warn(this, "Empty prompt received, cannot start conversation");
            userHandler.onError(new IllegalArgumentException(
                "Cannot process empty query. Please try again."));
            if (onCompletionCallback != null) {
                onCompletionCallback.run();
            }
            return;
        }

        isConversationActive = true;
        isCancelled = false;
        conversationHistory.clear();
        accumulatedAssistantContent.setLength(0); // Reset content accumulator
        rateLimitRetries = 0;
        toolCallRound = 0;

        // Add system message first
        conversationHistory.add(new ChatMessage(
            ChatMessage.ChatMessageRole.SYSTEM,
            apiClient.getCurrentContext()
        ));

        // Add existing history (preserving thinking data, tool calls, etc.)
        // Skip any system messages in the history since we just added our own
        if (existingHistory != null) {
            for (ChatMessage msg : existingHistory) {
                if (!ChatMessage.ChatMessageRole.SYSTEM.equals(msg.getRole())) {
                    conversationHistory.add(msg);
                }
            }
        }

        // Add new user message
        conversationHistory.add(new ChatMessage(ChatMessage.ChatMessageRole.USER, newUserPrompt));

        // Start the conversation loop
        userHandler.onStart();
        // Validate imported history before starting - existing history may have orphaned tool_calls
        validateAndRepairConversationHistory();

        continueConversation();
    }

    /**
     * Cancel the ongoing conversation
     */
    public void cancel() {
        isCancelled = true;
        isConversationActive = false;

        // Clean up any orphaned tool_calls in history from in-progress tool execution.
        // Tool execution may still be running on another thread; the flush in
        // executeToolsSequentially will also add results, but validate/repair catches
        // any remaining gaps.
        validateAndRepairConversationHistory();

        userHandler.onUpdate("\n❌ **Cancelled**\n");
        userHandler.onComplete("Conversation cancelled");

        // Notify completion callback
        if (onCompletionCallback != null) {
            onCompletionCallback.run();
        }
    }

    /**
     * Continue the conversation with the current message history.
     * Supports multi-turn tool calling with safety limit (max 10 rounds per iteration).
     */
    private void continueConversation() {
        if (!isConversationActive || isCancelled) {
            return;
        }

        // Check tool calling round limit (safety mechanism for infinite loops)
        if (toolCallRound >= maxToolRounds) {
            Msg.warn(this, String.format(
                "Reached maximum tool calling rounds (%d). Completing conversation to prevent infinite loops.",
                maxToolRounds
            ));
            userHandler.onUpdate(String.format(
                "\n**Maximum tool rounds reached (%d)** - Completing with current findings.\n\n",
                maxToolRounds
            ));
            isConversationActive = false;
            // Pass accumulated assistant content instead of a status message,
            // so ReAct iterations preserve actual investigation findings
            String accumulated = accumulatedAssistantContent.toString();
            if (accumulated.isEmpty()) {
                accumulated = "Maximum tool calling rounds reached - no content accumulated";
            }
            userHandler.onComplete(accumulated);
            if (onCompletionCallback != null) {
                onCompletionCallback.run();
            }
            return;
        }

        try {
            // Manage context window to prevent token overflow
            if (contextWindowManager != null) {
                try {
                    List<ChatMessage> managed = contextWindowManager.checkAndManage(
                        conversationHistory, availableFunctions).join();
                    if (managed != conversationHistory) {
                        conversationHistory.clear();
                        conversationHistory.addAll(managed);
                    }
                    // Pre-flight token logging (Phase 4)
                    ContextStatus status = contextWindowManager.getStatus(conversationHistory, availableFunctions).join();
                    // Msg.debug(this, String.format("Pre-flight: %d tokens, %d messages, %d%% used", status.getCurrentTokens(), conversationHistory.size(), status.getPercentageUsed()));
                } catch (Exception e) {
                    Msg.warn(this, "ContextWindowManager failed, falling back to legacy trimming: " + e.getMessage());
                    trimConversationHistory();
                }
            } else {
                trimConversationHistory(); // Legacy fallback
            }

            // Validate and repair any orphaned tool_calls before sending to API
            validateAndRepairConversationHistory();

            // Log conversation structure for debugging
            logConversationStructure();

            // Call LLM with current conversation history
            // Use streaming if provider supports it (Anthropic, OpenAI, LMStudio), otherwise blocking
            if (apiClient.getProvider() instanceof AnthropicPlatformApiProvider ||
                apiClient.getProvider() instanceof OpenAIPlatformApiProvider ||
                apiClient.getProvider() instanceof LMStudioProvider) {
                streamingConversationWithFunctions();
            } else {
                // Non-streaming providers rely on the selected provider/client timeout.
                CompletableFuture<String> apiFuture = CompletableFuture.supplyAsync(() -> {
                    try {
                        // Check cancellation before making API call
                        if (isCancelled) {
                            return null;
                        }

                        return apiClient.createChatCompletionWithFunctionsFullResponse(
                            conversationHistory, availableFunctions, toolChoiceMode);

                    } catch (Exception e) {
                        throw new RuntimeException(e);
                    }
                });

                apiFuture
                    .thenAccept(fullResponse -> {
                        // Check cancellation after API call
                        if (isCancelled || fullResponse == null) {
                            return;
                        }

                        // Parse the response to check for tool calls and finish_reason
                        handleLLMResponse(fullResponse);
                    })
                    .exceptionally(e -> {
                        Throwable cause = e.getCause() != null ? e.getCause() : e;

                        // Handle rate limit errors - always retry, never give up
                        String errorMsg = cause.getMessage() != null ? cause.getMessage() : "";
                        if (cause instanceof ghidrassist.apiprovider.exceptions.RateLimitException ||
                            errorMsg.contains("rate limit") ||
                            errorMsg.contains("429")) {

                            rateLimitRetries++;
                            Msg.warn(this, String.format("Rate limit exceeded during conversational tool calling (attempt %d). Retrying with backoff...",
                                rateLimitRetries));

                            // Backoff: 10s, 20s, 30s, ... capped at MAX_RATE_LIMIT_BACKOFF_SECONDS
                            int backoffSeconds = Math.min(10 * rateLimitRetries, MAX_RATE_LIMIT_BACKOFF_SECONDS);
                            userHandler.onUpdate(String.format("⏳ Rate limit hit. Pausing for %d seconds...\n",
                                backoffSeconds));

                            CompletableFuture.delayedExecutor(backoffSeconds, java.util.concurrent.TimeUnit.SECONDS)
                                .execute(() -> {
                                    if (isConversationActive && !isCancelled) {
                                        userHandler.onUpdate("🔄 Resuming...\n");
                                        continueConversation();
                                    }
                                });
                        } else {
                            // Non-rate-limit errors stop the conversation
                            isConversationActive = false;
                            userHandler.onError(cause instanceof Exception ? (Exception) cause : new Exception(cause));

                            if (onCompletionCallback != null) {
                                onCompletionCallback.run();
                            }
                        }
                        return null;
                    });
            }

        } catch (Exception e) {
            isConversationActive = false;
            userHandler.onError(e);

            // Notify completion callback
            if (onCompletionCallback != null) {
                onCompletionCallback.run();
            }
        }
    }

    /**
     * Stream conversation with functions using provider's streaming API.
     * Supports Anthropic, OpenAI, and LMStudio providers.
     * Text content streams immediately; tool calls execute after streaming completes.
     */
    private void streamingConversationWithFunctions() {
        try {
            if (apiClient.getProvider() instanceof AnthropicPlatformApiProvider) {
                streamWithAnthropicPlatformApiProvider();
            } else if (apiClient.getProvider() instanceof OpenAIPlatformApiProvider) {
                streamWithOpenAIPlatformApiProvider();
            } else if (apiClient.getProvider() instanceof LMStudioProvider) {
                streamWithLMStudioProvider();
            }
        } catch (Exception e) {
            isConversationActive = false;
            userHandler.onError(e);

            if (onCompletionCallback != null) {
                onCompletionCallback.run();
            }
        }
    }

    /**
     * Stream conversation using Anthropic provider.
     */
    private void streamWithAnthropicPlatformApiProvider() {
        try {
            AnthropicPlatformApiProvider provider = (AnthropicPlatformApiProvider) apiClient.getProvider();

            provider.streamChatCompletionWithFunctions(
                conversationHistory,
                availableFunctions,
                toolChoiceMode,
                new AnthropicPlatformApiProvider.StreamingFunctionHandler() {
                    @Override
                    public void onTextUpdate(String textDelta) {
                        // Accumulate content for max-rounds recovery
                        if (textDelta != null) {
                            accumulatedAssistantContent.append(textDelta);
                        }
                        // Stream text to UI immediately
                        javax.swing.SwingUtilities.invokeLater(() -> {
                            if (!isCancelled) {
                                userHandler.onUpdate(textDelta);
                            }
                        });
                    }

                    @Override
                    public void onStreamComplete(String stopReason, String fullText, String thinkingContent, String thinkingSignature, List<AnthropicPlatformApiProvider.ToolCall> toolCalls) {
                        // Create assistant message with text content
                        ChatMessage assistantMsg = new ChatMessage(ChatMessage.ChatMessageRole.ASSISTANT, fullText);

                        // Store thinking content and signature if present
                        if (thinkingContent != null && !thinkingContent.isEmpty()) {
                            assistantMsg.setThinkingContent(thinkingContent);
                        }
                        if (thinkingSignature != null && !thinkingSignature.isEmpty()) {
                            assistantMsg.setThinkingSignature(thinkingSignature);
                        }

                        // Only attach tool calls when stopReason indicates tool use.
                        // If stopReason is "stop" but streaming accumulated partial tool call deltas,
                        // attaching them creates orphaned tool_calls (no results will follow).
                        if ("tool_use".equals(stopReason) && !toolCalls.isEmpty()) {
                            JsonArray toolCallsArray = new JsonArray();
                            for (AnthropicPlatformApiProvider.ToolCall toolCall : toolCalls) {
                                JsonObject toolCallObj = new JsonObject();
                                toolCallObj.addProperty("id", toolCall.id);
                                toolCallObj.addProperty("type", "function");

                                JsonObject function = new JsonObject();
                                function.addProperty("name", toolCall.name);
                                function.addProperty("arguments", toolCall.arguments);
                                toolCallObj.add("function", function);

                                toolCallsArray.add(toolCallObj);
                            }

                            // Attach tool calls to assistant message
                            assistantMsg.setToolCalls(toolCallsArray);
                        } else if (!toolCalls.isEmpty()) {
                            Msg.warn(ConversationalToolHandler.this,
                                String.format("Discarding %d tool calls because stopReason='%s' (expected 'tool_use')",
                                    toolCalls.size(), stopReason));
                        }

                        // Add assistant message to conversation history
                        conversationHistory.add(assistantMsg);

                        if ("tool_use".equals(stopReason) && !toolCalls.isEmpty()) {
                            // Increment tool call round counter (multi-turn tracking)
                            toolCallRound++;
                            // Msg.debug(ConversationalToolHandler.this, String.format("Tool calling round %d/%d", toolCallRound, maxToolRounds));

                            // Execute tools after text streaming completes
                            handleToolCallsFromStream(toolCalls);
                        } else {
                            // Conversation complete - pass the full response text
                            handleConversationEndFromStream(fullText);
                        }
                    }

                    @Override
                    public void onError(Throwable error) {
                        // Handle rate limit errors - always retry, never give up
                        if (error instanceof RateLimitException ||
                            error.getMessage().contains("rate limit") ||
                            error.getMessage().contains("429")) {

                            rateLimitRetries++;
                            Msg.warn(ConversationalToolHandler.this,
                                String.format("Rate limit exceeded during streaming (attempt %d). Retrying with backoff...",
                                    rateLimitRetries));

                            int backoffSeconds = Math.min(10 * rateLimitRetries, MAX_RATE_LIMIT_BACKOFF_SECONDS);
                            userHandler.onUpdate(String.format("⏳ Rate limit hit. Pausing for %d seconds...\n",
                                backoffSeconds));

                            CompletableFuture.delayedExecutor(backoffSeconds, java.util.concurrent.TimeUnit.SECONDS)
                                .execute(() -> {
                                    if (isConversationActive && !isCancelled) {
                                        userHandler.onUpdate("🔄 Resuming...\n");
                                        continueConversation();
                                    }
                                });
                        } else {
                            // Non-rate-limit errors stop the conversation
                            isConversationActive = false;

                            // If tool calls have been executed, gracefully complete with
                            // accumulated content instead of losing all findings
                            if (toolCallRound > 0 && accumulatedAssistantContent.length() > 0) {
                                Msg.warn(ConversationalToolHandler.this,
                                    String.format("Stream error after %d tool rounds, completing with accumulated content: %s",
                                        toolCallRound, error.getMessage()));
                                userHandler.onUpdate(String.format(
                                    "\n**Stream interrupted after %d tool rounds** - Completing with current findings.\n\n",
                                    toolCallRound));
                                userHandler.onComplete(accumulatedAssistantContent.toString());
                            } else {
                                userHandler.onError(error);
                            }

                            if (onCompletionCallback != null) {
                                onCompletionCallback.run();
                            }
                        }
                    }

                    @Override
                    public boolean shouldContinue() {
                        return !isCancelled && isConversationActive;
                    }
                }
            );

        } catch (Exception e) {
            isConversationActive = false;
            userHandler.onError(e);

            if (onCompletionCallback != null) {
                onCompletionCallback.run();
            }
        }
    }

    /**
     * Stream conversation using OpenAI provider.
     */
    private void streamWithOpenAIPlatformApiProvider() {
        try {
            OpenAIPlatformApiProvider provider = (OpenAIPlatformApiProvider) apiClient.getProvider();

            provider.streamChatCompletionWithFunctions(
                conversationHistory,
                availableFunctions,
                toolChoiceMode,
                new OpenAIPlatformApiProvider.StreamingFunctionHandler() {
                    @Override
                    public void onTextUpdate(String textDelta) {
                        // Accumulate content for max-rounds recovery
                        if (textDelta != null) {
                            accumulatedAssistantContent.append(textDelta);
                        }
                        javax.swing.SwingUtilities.invokeLater(() -> {
                            if (!isCancelled) {
                                userHandler.onUpdate(textDelta);
                            }
                        });
                    }

                    @Override
                    public void onStreamComplete(String stopReason, String fullText, String reasoningContent, List<OpenAIPlatformApiProvider.ToolCall> toolCalls) {
                        ChatMessage assistantMsg = new ChatMessage(ChatMessage.ChatMessageRole.ASSISTANT, fullText);

                        // Store reasoning_content so it can be passed back on the next turn (DeepSeek requirement)
                        if (reasoningContent != null && !reasoningContent.isEmpty()) {
                            assistantMsg.setThinkingContent(reasoningContent);
                        }

                        // Only attach tool calls when stopReason indicates tool calling.
                        // If stopReason is "stop" but streaming accumulated partial tool call deltas,
                        // attaching them creates orphaned tool_calls (no results will follow).
                        if ("tool_calls".equals(stopReason) && !toolCalls.isEmpty()) {
                            JsonArray toolCallsArray = new JsonArray();
                            for (OpenAIPlatformApiProvider.ToolCall toolCall : toolCalls) {
                                JsonObject toolCallObj = new JsonObject();
                                toolCallObj.addProperty("id", toolCall.id);
                                toolCallObj.addProperty("type", "function");

                                JsonObject function = new JsonObject();
                                function.addProperty("name", toolCall.name);
                                function.addProperty("arguments", toolCall.arguments);
                                toolCallObj.add("function", function);

                                toolCallsArray.add(toolCallObj);
                            }
                            assistantMsg.setToolCalls(toolCallsArray);
                        } else if (!toolCalls.isEmpty()) {
                            Msg.warn(ConversationalToolHandler.this,
                                String.format("Discarding %d tool calls because stopReason='%s' (expected 'tool_calls')",
                                    toolCalls.size(), stopReason));
                        }

                        conversationHistory.add(assistantMsg);

                        if ("tool_calls".equals(stopReason) && !toolCalls.isEmpty()) {
                            // Increment tool call round counter (multi-turn tracking)
                            toolCallRound++;
                            // Msg.debug(ConversationalToolHandler.this, String.format("Tool calling round %d/%d", toolCallRound, maxToolRounds));

                            handleToolCallsFromOpenAIStream(toolCalls);
                        } else {
                            // Conversation complete - pass the full response text
                            handleConversationEndFromStream(fullText);
                        }
                    }

                    @Override
                    public void onError(Throwable error) {
                        handleStreamingError(error);
                    }

                    @Override
                    public boolean shouldContinue() {
                        return !isCancelled && isConversationActive;
                    }
                }
            );

        } catch (Exception e) {
            isConversationActive = false;
            userHandler.onError(e);

            if (onCompletionCallback != null) {
                onCompletionCallback.run();
            }
        }
    }

    /**
     * Stream conversation using LMStudio provider.
     */
    private void streamWithLMStudioProvider() {
        try {
            LMStudioProvider provider = (LMStudioProvider) apiClient.getProvider();

            provider.streamChatCompletionWithFunctions(
                conversationHistory,
                availableFunctions,
                toolChoiceMode,
                new LMStudioProvider.StreamingFunctionHandler() {
                    @Override
                    public void onTextUpdate(String textDelta) {
                        // Accumulate content for max-rounds recovery
                        if (textDelta != null) {
                            accumulatedAssistantContent.append(textDelta);
                        }
                        javax.swing.SwingUtilities.invokeLater(() -> {
                            if (!isCancelled) {
                                userHandler.onUpdate(textDelta);
                            }
                        });
                    }

                    @Override
                    public void onStreamComplete(String stopReason, String fullText, List<LMStudioProvider.ToolCall> toolCalls) {
                        ChatMessage assistantMsg = new ChatMessage(ChatMessage.ChatMessageRole.ASSISTANT, fullText);

                        // Only attach tool calls when stopReason indicates tool calling.
                        // If stopReason is "stop" but streaming accumulated partial tool call deltas,
                        // attaching them creates orphaned tool_calls (no results will follow).
                        if ("tool_calls".equals(stopReason) && !toolCalls.isEmpty()) {
                            JsonArray toolCallsArray = new JsonArray();
                            for (LMStudioProvider.ToolCall toolCall : toolCalls) {
                                JsonObject toolCallObj = new JsonObject();
                                toolCallObj.addProperty("id", toolCall.id);
                                toolCallObj.addProperty("type", "function");

                                JsonObject function = new JsonObject();
                                function.addProperty("name", toolCall.name);
                                function.addProperty("arguments", toolCall.arguments);
                                toolCallObj.add("function", function);

                                toolCallsArray.add(toolCallObj);
                            }
                            assistantMsg.setToolCalls(toolCallsArray);
                        } else if (!toolCalls.isEmpty()) {
                            Msg.warn(ConversationalToolHandler.this,
                                String.format("Discarding %d tool calls because stopReason='%s' (expected 'tool_calls')",
                                    toolCalls.size(), stopReason));
                        }

                        conversationHistory.add(assistantMsg);

                        if ("tool_calls".equals(stopReason) && !toolCalls.isEmpty()) {
                            // Increment tool call round counter (multi-turn tracking)
                            toolCallRound++;
                            // Msg.debug(ConversationalToolHandler.this, String.format("Tool calling round %d/%d", toolCallRound, maxToolRounds));

                            handleToolCallsFromLMStudioStream(toolCalls);
                        } else {
                            // Conversation complete - pass the full response text
                            handleConversationEndFromStream(fullText);
                        }
                    }

                    @Override
                    public void onError(Throwable error) {
                        handleStreamingError(error);
                    }

                    @Override
                    public boolean shouldContinue() {
                        return !isCancelled && isConversationActive;
                    }
                }
            );

        } catch (Exception e) {
            isConversationActive = false;
            userHandler.onError(e);

            if (onCompletionCallback != null) {
                onCompletionCallback.run();
            }
        }
    }

    /**
     * Common error handling for streaming providers.
     */
    private void handleStreamingError(Throwable error) {
        if (error instanceof RateLimitException ||
            error.getMessage().contains("rate limit") ||
            error.getMessage().contains("429")) {

            rateLimitRetries++;
            Msg.warn(ConversationalToolHandler.this,
                String.format("Rate limit exceeded during streaming (attempt %d). Retrying with backoff...",
                    rateLimitRetries));

            int backoffSeconds = Math.min(10 * rateLimitRetries, MAX_RATE_LIMIT_BACKOFF_SECONDS);
            userHandler.onUpdate(String.format("⏳ Rate limit hit. Pausing for %d seconds...\n",
                backoffSeconds));

            CompletableFuture.delayedExecutor(backoffSeconds, java.util.concurrent.TimeUnit.SECONDS)
                .execute(() -> {
                    if (isConversationActive && !isCancelled) {
                        userHandler.onUpdate("🔄 Resuming...\n");
                        continueConversation();
                    }
                });
        } else {
            isConversationActive = false;

            // If tool calls have been executed, gracefully complete with
            // accumulated content instead of losing all findings
            if (toolCallRound > 0 && accumulatedAssistantContent.length() > 0) {
                Msg.warn(this, String.format(
                    "Stream error after %d tool rounds, completing with accumulated content: %s",
                    toolCallRound, error.getMessage()));
                userHandler.onUpdate(String.format(
                    "\n**Stream interrupted after %d tool rounds** - Completing with current findings.\n\n",
                    toolCallRound));
                userHandler.onComplete(accumulatedAssistantContent.toString());
            } else {
                userHandler.onError(error);
            }

            if (onCompletionCallback != null) {
                onCompletionCallback.run();
            }
        }
    }

    /**
     * Handle tool calls from streaming response.
     * Simplified version of handleToolCalls for use with streaming.
     */
    private void handleToolCallsFromStream(List<AnthropicPlatformApiProvider.ToolCall> toolCalls) {
        try {
            // Convert AnthropicPlatformApiProvider.ToolCall to JsonArray format expected by existing methods
            JsonArray toolCallsArray = new JsonArray();
            for (AnthropicPlatformApiProvider.ToolCall toolCall : toolCalls) {
                JsonObject toolCallObj = new JsonObject();
                toolCallObj.addProperty("id", toolCall.id);
                toolCallObj.addProperty("type", "function");

                JsonObject function = new JsonObject();
                function.addProperty("name", toolCall.name);
                function.addProperty("arguments", toolCall.arguments);
                toolCallObj.add("function", function);

                toolCallsArray.add(toolCallObj);
            }

            // Execute tools sequentially using existing infrastructure
            executeToolsSequentially(toolCallsArray, 0, new ArrayList<>());

        } catch (Exception e) {
            Msg.error(this, "Error handling tool calls from stream: " + e.getMessage());
            isConversationActive = false;
            userHandler.onError(e);

            if (onCompletionCallback != null) {
                onCompletionCallback.run();
            }
        }
    }

    /**
     * Handle tool calls from OpenAI streaming response.
     */
    private void handleToolCallsFromOpenAIStream(List<OpenAIPlatformApiProvider.ToolCall> toolCalls) {
        try {
            JsonArray toolCallsArray = new JsonArray();
            for (OpenAIPlatformApiProvider.ToolCall toolCall : toolCalls) {
                JsonObject toolCallObj = new JsonObject();
                toolCallObj.addProperty("id", toolCall.id);
                toolCallObj.addProperty("type", "function");

                JsonObject function = new JsonObject();
                function.addProperty("name", toolCall.name);
                function.addProperty("arguments", toolCall.arguments);
                toolCallObj.add("function", function);

                toolCallsArray.add(toolCallObj);
            }

            executeToolsSequentially(toolCallsArray, 0, new ArrayList<>());

        } catch (Exception e) {
            Msg.error(this, "Error handling tool calls from OpenAI stream: " + e.getMessage());
            isConversationActive = false;
            userHandler.onError(e);

            if (onCompletionCallback != null) {
                onCompletionCallback.run();
            }
        }
    }

    /**
     * Handle tool calls from LMStudio streaming response.
     */
    private void handleToolCallsFromLMStudioStream(List<LMStudioProvider.ToolCall> toolCalls) {
        try {
            JsonArray toolCallsArray = new JsonArray();
            for (LMStudioProvider.ToolCall toolCall : toolCalls) {
                JsonObject toolCallObj = new JsonObject();
                toolCallObj.addProperty("id", toolCall.id);
                toolCallObj.addProperty("type", "function");

                JsonObject function = new JsonObject();
                function.addProperty("name", toolCall.name);
                function.addProperty("arguments", toolCall.arguments);
                toolCallObj.add("function", function);

                toolCallsArray.add(toolCallObj);
            }

            executeToolsSequentially(toolCallsArray, 0, new ArrayList<>());

        } catch (Exception e) {
            Msg.error(this, "Error handling tool calls from LMStudio stream: " + e.getMessage());
            isConversationActive = false;
            userHandler.onError(e);

            if (onCompletionCallback != null) {
                onCompletionCallback.run();
            }
        }
    }

    /**
     * Handle conversation end from streaming (no tool calls).
     */
    private void handleConversationEndFromStream(String fullText) {
        isConversationActive = false;

        // Pass the accumulated response text to onComplete
        String responseText = fullText != null ? fullText : "";

        javax.swing.SwingUtilities.invokeLater(() -> {
            userHandler.onComplete(responseText);
        });

        // Notify completion callback
        if (onCompletionCallback != null) {
            onCompletionCallback.run();
        }
    }

    /**
     * Handle the LLM response and determine next action based on finish_reason
     */
    private void handleLLMResponse(String rawResponse) {
        try {
            // Check cancellation before processing response
            if (isCancelled) {
                return;
            }

            // Msg.debug(this, "Raw LLM response: " + (rawResponse != null ? rawResponse : "NULL"));

            // Validate response is not null or empty
            if (rawResponse == null || rawResponse.trim().isEmpty()) {
                throw new IllegalArgumentException("LLM response is null or empty");
            }

            // Parse the complete response including metadata
            JsonElement responseElement = JsonParser.parseString(rawResponse);
            if (responseElement == null || responseElement.isJsonNull()) {
                throw new IllegalArgumentException("LLM response parsed to null JSON");
            }

            if (!responseElement.isJsonObject()) {
                throw new IllegalArgumentException("LLM response is not a JSON object: " + responseElement.getClass().getSimpleName());
            }

            JsonObject responseObj = responseElement.getAsJsonObject();

            // Extract finish_reason from choices array
            String finishReason = extractFinishReason(responseObj);
            JsonObject assistantMessage = extractAssistantMessage(responseObj);

            Msg.debug(this, "LLM finish_reason: " + finishReason);

            if ("tool_calls".equals(finishReason) || "tool_use".equals(finishReason)) {
                handleToolCalls(assistantMessage, rawResponse);
            } else if ("stop".equals(finishReason) || "unknown".equals(finishReason)) {
                // Handle normal completion (no tools needed) or unknown finish_reason
                handleConversationEnd(assistantMessage);
            } else {
                // Other finish_reason types (length, content_filter, etc.)
                Msg.debug(this, "LLM finished with reason: " + finishReason + ", ending conversation");
                handleConversationEnd(assistantMessage);
            }

        } catch (Exception e) {
            Msg.error(this, "Error handling LLM response: " + e.getMessage());
            Msg.error(this, "Response content: " + (rawResponse != null ? rawResponse.substring(0, Math.min(500, rawResponse.length())) : "NULL"));
            isConversationActive = false;
            userHandler.onError(e);

            // Notify completion callback
            if (onCompletionCallback != null) {
                onCompletionCallback.run();
            }
        }
    }

    /**
     * Extract finish_reason from the LLM response
     */
    private String extractFinishReason(JsonObject responseObj) {
        try {
            if (responseObj != null && responseObj.has("choices")) {
                JsonElement choicesElement = responseObj.get("choices");
                if (choicesElement != null && !choicesElement.isJsonNull() && choicesElement.isJsonArray()) {
                    JsonArray choices = choicesElement.getAsJsonArray();
                    if (choices.size() > 0) {
                        JsonElement firstChoiceElement = choices.get(0);
                        if (firstChoiceElement != null && !firstChoiceElement.isJsonNull() && firstChoiceElement.isJsonObject()) {
                            JsonObject firstChoice = firstChoiceElement.getAsJsonObject();
                            if (firstChoice.has("finish_reason")) {
                                JsonElement finishReasonElement = firstChoice.get("finish_reason");
                                if (finishReasonElement != null && !finishReasonElement.isJsonNull()) {
                                    return finishReasonElement.getAsString();
                                }
                            }
                        }
                    }
                }
            }
            return "unknown";
        } catch (Exception e) {
            Msg.warn(this, "Could not extract finish_reason: " + e.getMessage());
            return "unknown";
        }
    }

    /**
     * Extract the assistant message from the LLM response
     */
    private JsonObject extractAssistantMessage(JsonObject responseObj) {
        try {
            if (responseObj != null && responseObj.has("choices")) {
                JsonElement choicesElement = responseObj.get("choices");
                if (choicesElement != null && !choicesElement.isJsonNull() && choicesElement.isJsonArray()) {
                    JsonArray choices = choicesElement.getAsJsonArray();
                    if (choices.size() > 0) {
                        JsonElement firstChoiceElement = choices.get(0);
                        if (firstChoiceElement != null && !firstChoiceElement.isJsonNull() && firstChoiceElement.isJsonObject()) {
                            JsonObject firstChoice = firstChoiceElement.getAsJsonObject();
                            if (firstChoice.has("message")) {
                                JsonElement messageElement = firstChoice.get("message");
                                if (messageElement != null && !messageElement.isJsonNull() && messageElement.isJsonObject()) {
                                    return messageElement.getAsJsonObject();
                                }
                            }
                        }
                    }
                }
            }
            // Fallback: try to find message directly
            if (responseObj != null && responseObj.has("message")) {
                JsonElement messageElement = responseObj.get("message");
                if (messageElement != null && !messageElement.isJsonNull() && messageElement.isJsonObject()) {
                    return messageElement.getAsJsonObject();
                }
            }
            return new JsonObject();
        } catch (Exception e) {
            Msg.warn(this, "Could not extract assistant message: " + e.getMessage());
            return new JsonObject();
        }
    }

    /**
     * Handle tool calls when finish_reason is "tool_calls"
     */
    private void handleToolCalls(JsonObject assistantMessage, String rawResponse) {
        try {
            // Create assistant message with tool calls
            String content = null;
            if (assistantMessage.has("content")) {
                JsonElement contentElement = assistantMessage.get("content");
                if (contentElement != null && !contentElement.isJsonNull()) {
                    content = contentElement.getAsString();
                }
            }

            ChatMessage assistantMsg = new ChatMessage(
                ChatMessage.ChatMessageRole.ASSISTANT,
                content
            );

            // Add tool calls to the assistant message
            if (assistantMessage.has("tool_calls")) {
                assistantMsg.setToolCalls(assistantMessage.getAsJsonArray("tool_calls"));
            }

            // Store reasoning_content so it can be passed back on the next turn (DeepSeek requirement)
            if (assistantMessage.has("reasoning_content") && !assistantMessage.get("reasoning_content").isJsonNull()) {
                String reasoningContent = assistantMessage.get("reasoning_content").getAsString();
                if (!reasoningContent.isEmpty()) {
                    assistantMsg.setThinkingContent(reasoningContent);
                }
            }

            conversationHistory.add(assistantMsg);

            // Extract tool calls
            JsonArray toolCalls = null;
            if (assistantMessage.has("tool_calls")) {
                toolCalls = assistantMessage.getAsJsonArray("tool_calls");
            } else if (assistantMessage.has("content")) {
                // Try to parse tool calls from content
                // This line should not be reached now, but adding safety
                String contentStr = "";
                if (assistantMessage.has("content")) {
                    JsonElement contentElement = assistantMessage.get("content");
                    if (contentElement != null && !contentElement.isJsonNull()) {
                        contentStr = contentElement.getAsString();
                    }
                }
                JsonObject contentObj = JsonParser.parseString(contentStr).getAsJsonObject();
                if (contentObj.has("tool_calls")) {
                    toolCalls = contentObj.getAsJsonArray("tool_calls");
                }
            }

            if (toolCalls == null || toolCalls.size() == 0) {
                Msg.warn(this, "No tool calls found despite finish_reason being tool_calls");
                handleConversationEnd(assistantMessage);
                return;
            }

            // Accumulate content for max-rounds recovery (non-streaming path)
            if (content != null && !content.trim().isEmpty()) {
                accumulatedAssistantContent.append(content);
            }

            // Display text response if present, before tool execution metadata
            if (content != null && !content.trim().isEmpty()) {
                String filteredContent = responseProcessor.filterThinkBlocks(content);
                if (filteredContent != null && !filteredContent.trim().isEmpty()) {
                    javax.swing.SwingUtilities.invokeLater(() -> {
                        userHandler.onUpdate("\n" + filteredContent + "\n\n");
                    });
                }
            }

            // Execute tools and collect results
            executeToolsSequentially(toolCalls, 0, new ArrayList<>());

        } catch (Exception e) {
            Msg.error(this, "Error handling tool calls: " + e.getMessage());
            isConversationActive = false;
            userHandler.onError(e);

            // Notify completion callback
            if (onCompletionCallback != null) {
                onCompletionCallback.run();
            }
        }
    }

    /**
     * Execute tools sequentially and collect results
     */
    private void executeToolsSequentially(JsonArray toolCalls, int index, List<JsonObject> toolResults) {
        // Check cancellation before processing next tool
        if (isCancelled) {
            // Flush any collected results to prevent orphaned tool_calls in history.
            // Add placeholders for remaining tools that won't execute.
            for (int remaining = index; remaining < toolCalls.size(); remaining++) {
                String cancelledId;
                try {
                    cancelledId = extractToolCallId(toolCalls.get(remaining).getAsJsonObject());
                } catch (Exception e) {
                    cancelledId = "call_cancelled_" + remaining;
                }
                JsonObject cancelResult = new JsonObject();
                cancelResult.addProperty("tool_call_id", cancelledId);
                cancelResult.addProperty("role", "tool");
                cancelResult.addProperty("content", "Error: Tool execution was cancelled.");
                toolResults.add(cancelResult);
            }
            addToolResultsToConversation(toolResults);
            return;
        }

        if (index >= toolCalls.size()) {
            // All tools executed, add results to conversation and continue
            addToolResultsToConversation(toolResults);

            // Signal tool execution to handler
            userHandler.onToolsExecuted(toolCalls.size());

            // Add a small delay before making the next API call to avoid rapid sequential requests
            // that could trigger rate limits
            CompletableFuture.delayedExecutor(500, java.util.concurrent.TimeUnit.MILLISECONDS)
                .execute(() -> {
                    if (!isCancelled) {
                        continueConversation();
                    }
                });
            return;
        }

        JsonObject toolCall = toolCalls.get(index).getAsJsonObject();
        executeSingleTool(toolCall)
            .thenAccept(result -> {
                toolResults.add(result); // Always collect the result even if cancelled
                if (!isCancelled) {
                    // Add small delay between tool executions to be gentle on API rate limits
                    CompletableFuture.delayedExecutor(200, java.util.concurrent.TimeUnit.MILLISECONDS)
                        .execute(() -> {
                            // Re-enter executeToolsSequentially which checks isCancelled and flushes
                            executeToolsSequentially(toolCalls, index + 1, toolResults);
                        });
                } else {
                    // Cancelled: flush current results + placeholders for remaining tools
                    executeToolsSequentially(toolCalls, index + 1, toolResults);
                }
            })
            .exceptionally(throwable -> {
                try {
                    if (!isCancelled) {
                        Msg.error(this, "Tool execution failed: " + throwable.getMessage());

                        // Safely extract tool call ID - don't let this throw and break the chain
                        String errorToolCallId;
                        try {
                            errorToolCallId = extractToolCallId(toolCall);
                        } catch (Exception idError) {
                            Msg.warn(this, "Failed to extract tool call ID in error handler: " + idError.getMessage());
                            errorToolCallId = "call_error_" + index;
                        }

                        // Create error result and continue
                        JsonObject errorResult = new JsonObject();
                        errorResult.addProperty("tool_call_id", errorToolCallId);
                        errorResult.addProperty("role", "tool");
                        errorResult.addProperty("content", "Error: " + throwable.getMessage());
                        toolResults.add(errorResult);

                        // Add same delay for error case to maintain consistent pacing
                        CompletableFuture.delayedExecutor(200, java.util.concurrent.TimeUnit.MILLISECONDS)
                            .execute(() -> {
                                if (!isCancelled) {
                                    executeToolsSequentially(toolCalls, index + 1, toolResults);
                                }
                            });
                    }
                } catch (Exception outerError) {
                    // Last-resort catch: ensure the chain never breaks silently
                    Msg.error(this, "Critical error in tool execution error handler: " + outerError.getMessage());
                    // Still try to continue the chain with remaining tools
                    JsonObject fallbackResult = new JsonObject();
                    fallbackResult.addProperty("tool_call_id", "call_error_" + index);
                    fallbackResult.addProperty("role", "tool");
                    fallbackResult.addProperty("content", "Error: Internal error during tool execution");
                    toolResults.add(fallbackResult);

                    CompletableFuture.delayedExecutor(200, java.util.concurrent.TimeUnit.MILLISECONDS)
                        .execute(() -> {
                            if (!isCancelled) {
                                executeToolsSequentially(toolCalls, index + 1, toolResults);
                            }
                        });
                }
                return null;
            });
    }

    /**
     * Execute a single tool and return the result
     */
    private CompletableFuture<JsonObject> executeSingleTool(JsonObject toolCall) {
        try {
            // Check cancellation before executing tool
            if (isCancelled) {
                return CompletableFuture.failedFuture(new Exception("Execution cancelled"));
            }

            String toolName = extractToolName(toolCall);
            JsonObject arguments = extractToolArguments(toolCall);
            String toolCallId = extractToolCallId(toolCall);

            // Execute via ToolRegistry with proper transaction handling
            return executeToolWithTransaction(toolName, arguments)
                .thenApply(result -> {
                    // Check cancellation before processing result
                    if (isCancelled) {
                        throw new RuntimeException("Execution cancelled");
                    }

                    // Debug logging for development (keep for troubleshooting)
                    Msg.debug(this, String.format("Tool '%s' completed: success=%s, length=%d",
                        toolName, result.isSuccess(),
                        result.getContent() != null ? result.getContent().length() : 0));

                    // Create tool result for conversation
                    JsonObject toolResult = new JsonObject();
                    toolResult.addProperty("tool_call_id", toolCallId);
                    toolResult.addProperty("role", "tool");
                    toolResult.addProperty("content", result.getContent());

                    return toolResult;
                });

        } catch (Exception e) {
            return CompletableFuture.failedFuture(e);
        }
    }

    /**
     * Add tool results to conversation history
     */
    private void addToolResultsToConversation(List<JsonObject> toolResults) {
        for (JsonObject result : toolResults) {
            // Safely extract content
            String content = "";
            if (result.has("content")) {
                JsonElement contentElement = result.get("content");
                if (contentElement != null && !contentElement.isJsonNull()) {
                    content = contentElement.getAsString();
                }
            }

            // Truncate tool results via ContextWindowManager if available
            if (contextWindowManager != null && content != null && !content.isEmpty()) {
                content = contextWindowManager.truncateToolResult(content);
            }

            // Safely extract tool_call_id
            String toolCallId = "";
            if (result.has("tool_call_id")) {
                JsonElement idElement = result.get("tool_call_id");
                if (idElement != null && !idElement.isJsonNull()) {
                    toolCallId = idElement.getAsString();
                }
            }

            ChatMessage toolMessage = new ChatMessage(ChatMessage.ChatMessageRole.TOOL, content);
            toolMessage.setToolCallId(toolCallId);
            conversationHistory.add(toolMessage);
        }
    }

    /**
     * Handle conversation end when finish_reason is "stop"
     */
    private void handleConversationEnd(JsonObject assistantMessage) {
        isConversationActive = false;

        try {
            // Extract and filter the final response
            String content = "";
            if (assistantMessage != null && assistantMessage.has("content")) {
                JsonElement contentElement = assistantMessage.get("content");
                if (contentElement != null && !contentElement.isJsonNull()) {
                    content = contentElement.getAsString();
                    // Accumulate content for max-rounds recovery (non-streaming path)
                    accumulatedAssistantContent.append(content);
                }
            }

            // Handle case where content is null or empty
            if (content == null || content.trim().isEmpty()) {
                if (toolCallRound > 0) {
                    content = "Tool execution completed. Continuing analysis.";
                    Msg.info(this, "LLM response had no text content after " + toolCallRound + " tool rounds");
                } else {
                    content = "";
                    Msg.warn(this, "LLM response had no content and no tool calls; returning empty completion");
                }
            }

            String filteredContent = responseProcessor.filterThinkBlocks(content);

            // Debug logging for final response
            // Msg.info(this, String.format("Final LLM response: length=%d",filteredContent != null ? filteredContent.length() : 0));
            if (filteredContent != null && filteredContent.length() > 0) {
                // f(this, "Final response preview: " + (filteredContent.length() > 200 ? filteredContent.substring(0, 200) + "..." : filteredContent));
            }

            // Send only the final LLM response (tool execution messages were already sent individually)
            javax.swing.SwingUtilities.invokeLater(() -> {
                userHandler.onUpdate("\n" + filteredContent);
                userHandler.onComplete("\n" + filteredContent);
            });

        } catch (Exception e) {
            Msg.error(this, "Error handling conversation end: " + e.getMessage());
            // Provide fallback response
            javax.swing.SwingUtilities.invokeLater(() -> {
                userHandler.onUpdate("I encountered an error processing the response. Please try again.");
                userHandler.onComplete("Error processing response");
            });
        }

        // Notify completion callback
        if (onCompletionCallback != null) {
            onCompletionCallback.run();
        }
    }

    /**
     * Extract tool name from tool call
     */
    private String extractToolName(JsonObject toolCall) {
        if (toolCall.has("function")) {
            JsonObject function = toolCall.getAsJsonObject("function");
            if (function != null && function.has("name") && !function.get("name").isJsonNull()) {
                return function.get("name").getAsString();
            }
        } else if (toolCall.has("name") && !toolCall.get("name").isJsonNull()) {
            return toolCall.get("name").getAsString();
        }

        Msg.error(this, "No tool name found in tool call: " + toolCall.toString());
        throw new IllegalArgumentException("No tool name found in tool call: " + toolCall.toString());
    }

    /**
     * Extract arguments from tool call
     */
    private JsonObject extractToolArguments(JsonObject toolCall) {
        JsonObject arguments = new JsonObject();

        try {
            if (toolCall.has("function")) {
                JsonObject function = toolCall.getAsJsonObject("function");
                if (function != null && function.has("arguments") && !function.get("arguments").isJsonNull()) {
                    JsonElement argsElement = function.get("arguments");
                    if (argsElement.isJsonObject()) {
                        arguments = argsElement.getAsJsonObject();
                    } else if (argsElement.isJsonPrimitive()) {
                        // Parse string arguments
                        String argsStr = argsElement.getAsString();
                        if (argsStr != null && !argsStr.trim().isEmpty()) {
                            arguments = JsonParser.parseString(argsStr).getAsJsonObject();
                        }
                    }
                }
            } else if (toolCall.has("arguments") && !toolCall.get("arguments").isJsonNull()) {
                JsonElement argsElement = toolCall.get("arguments");
                if (argsElement.isJsonObject()) {
                    arguments = argsElement.getAsJsonObject();
                } else if (argsElement.isJsonPrimitive()) {
                    String argsStr = argsElement.getAsString();
                    if (argsStr != null && !argsStr.trim().isEmpty()) {
                        arguments = JsonParser.parseString(argsStr).getAsJsonObject();
                    }
                }
            }
        } catch (Exception e) {
            Msg.error(this, "Failed to extract arguments from tool call: " + e.getMessage());
            Msg.error(this, "Tool call JSON: " + toolCall.toString());
        }

        return arguments;
    }

    /**
     * Extract tool call ID from tool call.
     * Handles null, JsonNull, and empty string cases that can occur when
     * streaming doesn't fully capture the tool call ID.
     */
    private String extractToolCallId(JsonObject toolCall) {
        if (toolCall.has("id")) {
            JsonElement idElement = toolCall.get("id");
            if (idElement != null && !idElement.isJsonNull() && idElement.isJsonPrimitive()) {
                String id = idElement.getAsString();
                if (id != null && !id.isEmpty()) {
                    return id;
                }
            }
            // ID field exists but is null/empty - generate deterministic fallback
            Msg.warn(this, "Tool call has null/empty ID, generating fallback. Tool call: " + toolCall.toString());
        }
        // Generate a deterministic fallback ID using tool name when possible
        String toolName = "unknown";
        try {
            toolName = extractToolName(toolCall);
        } catch (Exception ignored) {
            // extractToolName can throw - use default
        }
        return "call_fallback_" + toolName + "_" + System.currentTimeMillis();
    }

    /**
     * Trim conversation history to prevent token overflow.
     * Uses LLM-based summarization (with extractive fallback) to preserve context
     * about which tools were called and what was found, preventing infinite tool loops.
     */
    private void trimConversationHistory() {
        long totalChars = estimateTotalChars();
        boolean charThresholdExceeded = totalChars >= (long)(MAX_CONVERSATION_CHARS * COMPRESSION_THRESHOLD);
        boolean messageCountExceeded = conversationHistory.size() > MAX_CONVERSATION_HISTORY;

        if (!charThresholdExceeded && !messageCountExceeded) {
            return; // No trimming needed
        }

        // Msg.info(this, String.format("Context compression triggered: ~%d chars, %d messages",totalChars, conversationHistory.size()));

        // Identify beginning messages to always keep: system + first user query
        List<ChatMessage> beginning = new ArrayList<>();
        int firstUserIndex = -1;
        if (!conversationHistory.isEmpty()) {
            beginning.add(conversationHistory.get(0)); // System message
            for (int i = 1; i < conversationHistory.size(); i++) {
                if (ChatMessage.ChatMessageRole.USER.equals(conversationHistory.get(i).getRole())) {
                    beginning.add(conversationHistory.get(i));
                    firstUserIndex = i;
                    break;
                }
            }
        }

        // Find safe trim point for recent messages to keep
        int safeStartIndex = findSafeTrimPoint();
        // Ensure we keep at least MIN_RECENT_MESSAGES
        int minStartIndex = Math.max(0, conversationHistory.size() - MIN_RECENT_MESSAGES);
        if (safeStartIndex > minStartIndex) {
            // findSafeTrimPoint may return a point that keeps fewer messages than MIN_RECENT_MESSAGES;
            // walk backwards from minStartIndex to find a safe point
            for (int i = minStartIndex; i >= 0; i--) {
                if (isSafeTrimPoint(i)) {
                    safeStartIndex = i;
                    break;
                }
            }
        }

        // Collect messages to discard (between beginning and recent kept)
        int discardStart = (firstUserIndex >= 0) ? firstUserIndex + 1 : 1;
        List<ChatMessage> messagesToDiscard = new ArrayList<>();
        for (int i = discardStart; i < safeStartIndex; i++) {
            messagesToDiscard.add(conversationHistory.get(i));
        }

        if (messagesToDiscard.isEmpty()) {
            return; // Nothing to summarize
        }

        // Generate summary of discarded messages
        String summary = generateSummary(messagesToDiscard);

        // Rebuild history: beginning + summary + recent messages
        List<ChatMessage> trimmedHistory = new ArrayList<>(beginning);

        // Insert summary as a USER message
        ChatMessage summaryMessage = new ChatMessage(ChatMessage.ChatMessageRole.USER,
            "[Previous Investigation Summary]\n\n" + summary + "\n\n[End of Summary - Continuing Investigation]");
        trimmedHistory.add(summaryMessage);

        // Add recent messages from safe point to end
        for (int i = safeStartIndex; i < conversationHistory.size(); i++) {
            trimmedHistory.add(conversationHistory.get(i));
        }

        // Replace conversation history
        conversationHistory.clear();
        conversationHistory.addAll(trimmedHistory);

        // Msg.info(this, String.format("Context compressed: %d messages, ~%d chars (summarized %d messages)", conversationHistory.size(), estimateTotalChars(), messagesToDiscard.size()));
    }

    /**
     * Estimate total character count across all messages in the conversation.
     */
    private long estimateTotalChars() {
        long total = 0;
        for (ChatMessage msg : conversationHistory) {
            if (msg.getContent() != null) {
                total += msg.getContent().length();
            }
            if (msg.getToolCalls() != null) {
                total += msg.getToolCalls().toString().length();
            }
        }
        return total;
    }

    /**
     * Generate a summary of discarded messages using LLM-based summarization.
     * Falls back to extractive summary on failure.
     */
    private String generateSummary(List<ChatMessage> messagesToDiscard) {
        String formattedConversation = formatMessagesForSummary(messagesToDiscard);

        // Truncate to 40000 chars before sending to summarizer
        if (formattedConversation.length() > 40000) {
            formattedConversation = formattedConversation.substring(0, 40000) + "\n[... truncated ...]";
        }

        try {
            String prompt = String.format(SUMMARY_PROMPT, formattedConversation);
            List<ChatMessage> summaryMessages = new ArrayList<>();
            summaryMessages.add(new ChatMessage(ChatMessage.ChatMessageRole.USER, prompt));

            String summary = apiClient.getProvider().createChatCompletion(summaryMessages);

            if (summary != null && !summary.trim().isEmpty()) {
                // Msg.info(this, "LLM summarization succeeded");
                return summary.trim();
            }
        } catch (Exception e) {
            Msg.warn(this, "LLM summarization failed, using extractive fallback: " + e.getMessage());
        }

        return extractiveSummary(messagesToDiscard);
    }

    /**
     * Build an extractive summary from discarded messages.
     * Lists tools that were called and extracts key findings from assistant messages.
     */
    private String extractiveSummary(List<ChatMessage> messages) {
        Set<String> toolNames = new java.util.LinkedHashSet<>();
        List<String> keyFindings = new ArrayList<>();

        for (ChatMessage msg : messages) {
            // Collect tool names from tool_calls
            if (msg.getToolCalls() != null) {
                for (int i = 0; i < msg.getToolCalls().size(); i++) {
                    try {
                        JsonObject tc = msg.getToolCalls().get(i).getAsJsonObject();
                        if (tc.has("function")) {
                            JsonObject func = tc.getAsJsonObject("function");
                            if (func.has("name")) {
                                toolNames.add(func.get("name").getAsString());
                            }
                        }
                    } catch (Exception ignored) {
                    }
                }
            }

            // Extract key findings from assistant messages
            if (ChatMessage.ChatMessageRole.ASSISTANT.equals(msg.getRole()) && msg.getContent() != null) {
                String content = msg.getContent().toLowerCase();
                if (content.contains("found") || content.contains("discovered") ||
                    content.contains("identified") || content.contains("detected") ||
                    content.contains("result") || content.contains("analysis")) {
                    String finding = msg.getContent();
                    if (finding.length() > 200) {
                        finding = finding.substring(0, 200) + "...";
                    }
                    keyFindings.add(finding);
                }
            }
        }

        StringBuilder sb = new StringBuilder();
        if (!toolNames.isEmpty()) {
            sb.append("Tools already used: ").append(String.join(", ", toolNames)).append("\n\n");
        }
        if (!keyFindings.isEmpty()) {
            sb.append("Key findings:\n");
            for (String finding : keyFindings) {
                sb.append("- ").append(finding).append("\n");
            }
        }
        if (sb.length() == 0) {
            sb.append("Previous conversation contained ").append(messages.size())
              .append(" messages that were compressed.");
        }

        // Msg.info(this, "Using extractive summary fallback");
        return sb.toString();
    }

    /**
     * Format messages for the summarization prompt.
     * Truncates individual messages to keep the total manageable.
     */
    private String formatMessagesForSummary(List<ChatMessage> messages) {
        StringBuilder sb = new StringBuilder();
        for (ChatMessage msg : messages) {
            String role = msg.getRole().toString().toUpperCase();

            if (ChatMessage.ChatMessageRole.ASSISTANT.equals(msg.getRole())) {
                // Show tool calls if present
                if (msg.getToolCalls() != null && msg.getToolCalls().size() > 0) {
                    List<String> toolNamesList = new ArrayList<>();
                    for (int i = 0; i < msg.getToolCalls().size(); i++) {
                        try {
                            JsonObject tc = msg.getToolCalls().get(i).getAsJsonObject();
                            if (tc.has("function")) {
                                toolNamesList.add(tc.getAsJsonObject("function").get("name").getAsString());
                            }
                        } catch (Exception ignored) {
                        }
                    }
                    if (!toolNamesList.isEmpty()) {
                        sb.append(role).append(": [Called tools: ")
                          .append(String.join(", ", toolNamesList)).append("]\n");
                    }
                }
                if (msg.getContent() != null && !msg.getContent().isEmpty()) {
                    String content = msg.getContent();
                    if (content.length() > 2000) {
                        content = content.substring(0, 2000) + "...";
                    }
                    sb.append(role).append(": ").append(content).append("\n");
                }
            } else if (ChatMessage.ChatMessageRole.TOOL.equals(msg.getRole())) {
                String content = msg.getContent() != null ? msg.getContent() : "";
                if (content.length() > 500) {
                    content = content.substring(0, 500) + "...";
                }
                sb.append("TOOL_RESULT: ").append(content).append("\n");
            } else {
                String content = msg.getContent() != null ? msg.getContent() : "";
                if (content.length() > 2000) {
                    content = content.substring(0, 2000) + "...";
                }
                sb.append(role).append(": ").append(content).append("\n");
            }
            sb.append("\n");
        }
        return sb.toString();
    }

    /**
     * Find a safe point to start trimming that doesn't break tool call/result pairs
     */
    private int findSafeTrimPoint() {
        int targetSize = Math.max(MIN_RECENT_MESSAGES, MAX_CONVERSATION_HISTORY - 2);
        int startFromEnd = Math.min(targetSize, conversationHistory.size() - 1);

        // Start from desired point and look backwards for a safe boundary
        for (int lookback = 0; lookback < startFromEnd; lookback++) {
            int candidateIndex = conversationHistory.size() - startFromEnd + lookback;

            // Check if this is a safe cut point (not in middle of tool call/result sequence)
            if (isSafeTrimPoint(candidateIndex)) {
                return candidateIndex;
            }
        }

        // Fallback: keep last half of conversation
        return Math.max(1, conversationHistory.size() / 2);
    }

    /**
     * Check if we can safely trim at this point without breaking tool call/result pairs.
     * Scans backwards to ensure no preceding assistant message has tool results
     * that extend past the candidate index.
     */
    private boolean isSafeTrimPoint(int index) {
        if (index <= 0 || index >= conversationHistory.size()) {
            return false;
        }

        ChatMessage currentMessage = conversationHistory.get(index);

        // Don't trim if current message is a tool result (it needs its tool call)
        if (ChatMessage.ChatMessageRole.TOOL.equals(currentMessage.getRole())) {
            return false;
        }

        // Scan backwards from the candidate to find the nearest assistant message with tool_calls.
        // If found, verify all its tool results are before the candidate index.
        for (int i = index - 1; i >= 0; i--) {
            ChatMessage msg = conversationHistory.get(i);

            if (ChatMessage.ChatMessageRole.ASSISTANT.equals(msg.getRole()) &&
                msg.getToolCalls() != null && msg.getToolCalls().size() > 0) {

                // This assistant message has tool_calls. Check if any tool results
                // for it exist at or after the candidate index.
                int expectedResults = msg.getToolCalls().size();
                int foundResults = 0;
                for (int j = i + 1; j < conversationHistory.size(); j++) {
                    ChatMessage checkMsg = conversationHistory.get(j);
                    if (ChatMessage.ChatMessageRole.TOOL.equals(checkMsg.getRole())) {
                        foundResults++;
                        if (j >= index) {
                            // Tool result extends past the trim point - not safe
                            return false;
                        }
                    } else if (!ChatMessage.ChatMessageRole.TOOL.equals(checkMsg.getRole())) {
                        break; // Stop at non-tool message
                    }
                }

                // If we found fewer results than expected, some are missing
                // (validation will handle this, but don't trim here)
                if (foundResults < expectedResults) {
                    return false;
                }

                // This assistant message's tool results are all before the candidate - safe
                break;
            }

            // If we hit a user message, no need to look further back
            if (ChatMessage.ChatMessageRole.USER.equals(msg.getRole())) {
                break;
            }
        }

        return true;
    }

    /**
     * Validate and repair conversation history to prevent orphaned tool_calls.
     * Scans for assistant messages with tool_calls that lack matching tool result messages.
     * Called before each API call as a safety net.
     */
    private void validateAndRepairConversationHistory() {
        for (int i = 0; i < conversationHistory.size(); i++) {
            ChatMessage msg = conversationHistory.get(i);
            if (!ChatMessage.ChatMessageRole.ASSISTANT.equals(msg.getRole()) || msg.getToolCalls() == null) {
                continue;
            }

            JsonArray toolCalls = msg.getToolCalls();
            if (toolCalls.size() == 0) {
                continue;
            }

            // Collect all tool_call IDs from this assistant message
            List<String> expectedIds = new ArrayList<>();
            for (int tc = 0; tc < toolCalls.size(); tc++) {
                JsonObject toolCall = toolCalls.get(tc).getAsJsonObject();
                String id = null;
                if (toolCall.has("id")) {
                    JsonElement idEl = toolCall.get("id");
                    if (idEl != null && !idEl.isJsonNull() && idEl.isJsonPrimitive()) {
                        id = idEl.getAsString();
                    }
                }
                if (id != null && !id.isEmpty()) {
                    expectedIds.add(id);
                }
            }

            if (expectedIds.isEmpty()) {
                // All tool call IDs are null/empty - remove tool_calls entirely
                Msg.warn(this, "Removing tool_calls from assistant message at index " + i + ": all IDs are null/empty");
                msg.setToolCalls(null);
                continue;
            }

            // Check which IDs have matching tool result messages (look at messages after this one)
            List<String> foundIds = new ArrayList<>();
            for (int j = i + 1; j < conversationHistory.size(); j++) {
                ChatMessage resultMsg = conversationHistory.get(j);
                if (ChatMessage.ChatMessageRole.TOOL.equals(resultMsg.getRole()) && resultMsg.getToolCallId() != null) {
                    foundIds.add(resultMsg.getToolCallId());
                }
                // Stop scanning at the next assistant or user message
                if (ChatMessage.ChatMessageRole.ASSISTANT.equals(resultMsg.getRole()) ||
                    ChatMessage.ChatMessageRole.USER.equals(resultMsg.getRole())) {
                    break;
                }
            }

            // Check for missing results
            List<String> missingIds = new ArrayList<>();
            for (String expectedId : expectedIds) {
                if (!foundIds.contains(expectedId)) {
                    missingIds.add(expectedId);
                }
            }

            if (missingIds.isEmpty()) {
                continue; // All results present
            }

            if (missingIds.size() == expectedIds.size()) {
                // NO results found at all - remove tool_calls from assistant message
                Msg.warn(this, String.format(
                    "Removing orphaned tool_calls from assistant message at index %d: no matching tool results found for %d tool calls",
                    i, expectedIds.size()));
                msg.setToolCalls(null);
            } else {
                // SOME results missing - insert placeholder tool results
                Msg.warn(this, String.format(
                    "Inserting %d placeholder tool results for orphaned tool calls at index %d",
                    missingIds.size(), i));

                // Find insertion point: right after the last tool result for this assistant message
                int insertAt = i + 1;
                for (int j = i + 1; j < conversationHistory.size(); j++) {
                    ChatMessage checkMsg = conversationHistory.get(j);
                    if (ChatMessage.ChatMessageRole.TOOL.equals(checkMsg.getRole())) {
                        insertAt = j + 1;
                    } else {
                        break;
                    }
                }

                // Insert placeholders for missing IDs
                for (String missingId : missingIds) {
                    ChatMessage placeholder = new ChatMessage(ChatMessage.ChatMessageRole.TOOL,
                        "Error: Tool execution result was lost due to an internal error.");
                    placeholder.setToolCallId(missingId);
                    conversationHistory.add(insertAt, placeholder);
                    insertAt++;
                }
            }
        }

        // Reverse check: find tool result messages without a matching assistant tool_call.
        // The forward check above only validates assistant→results; this catches orphaned
        // results that may appear after trimming or loading external history.
        Set<String> allToolCallIds = new HashSet<>();
        for (ChatMessage msg : conversationHistory) {
            if (ChatMessage.ChatMessageRole.ASSISTANT.equals(msg.getRole()) && msg.getToolCalls() != null) {
                for (int tc = 0; tc < msg.getToolCalls().size(); tc++) {
                    JsonObject toolCall = msg.getToolCalls().get(tc).getAsJsonObject();
                    if (toolCall.has("id")) {
                        JsonElement idEl = toolCall.get("id");
                        if (idEl != null && !idEl.isJsonNull() && idEl.isJsonPrimitive()) {
                            allToolCallIds.add(idEl.getAsString());
                        }
                    }
                }
            }
        }

        // Remove tool result messages whose tool_call_id has no matching assistant tool_call
        Iterator<ChatMessage> it = conversationHistory.iterator();
        while (it.hasNext()) {
            ChatMessage msg = it.next();
            if (ChatMessage.ChatMessageRole.TOOL.equals(msg.getRole()) && msg.getToolCallId() != null) {
                if (!allToolCallIds.contains(msg.getToolCallId())) {
                    Msg.warn(this, "Removing orphaned tool result with tool_call_id=" + msg.getToolCallId()
                        + " (no matching assistant tool_call found)");
                    it.remove();
                }
            }
        }
    }

    /**
     * Log conversation structure for debugging tool call/result matching issues.
     * Only outputs at debug level.
     */
    private void logConversationStructure() {
        if (conversationHistory.isEmpty()) {
            return;
        }
        StringBuilder sb = new StringBuilder("Conversation structure (");
        sb.append(conversationHistory.size()).append(" messages):\n");
        for (int i = 0; i < conversationHistory.size(); i++) {
            ChatMessage msg = conversationHistory.get(i);
            sb.append(String.format("  [%d] role=%s", i, msg.getRole()));
            if (msg.getToolCalls() != null) {
                sb.append(String.format(" tool_calls=%d", msg.getToolCalls().size()));
            }
            if (msg.getToolCallId() != null) {
                sb.append(String.format(" tool_call_id=%s", msg.getToolCallId()));
            }
            int contentLen = msg.getContent() != null ? msg.getContent().length() : 0;
            sb.append(String.format(" content_len=%d", contentLen));
            sb.append("\n");
        }
        // Msg.debug(this, sb.toString());
    }

    /**
     * Format tool parameters for display in execution logs
     */
    private String formatToolParameters(JsonObject arguments) {
        if (arguments == null || arguments.size() == 0) {
            return "";
        }

        StringBuilder params = new StringBuilder();
        boolean first = true;

        for (String key : arguments.keySet()) {
            if (!first) {
                params.append(", ");
            }
            first = false;

            JsonElement value = arguments.get(key);
            if (value.isJsonPrimitive()) {
                String strValue = value.getAsString();
                // Add quotes around string values for clarity
                if (value.getAsJsonPrimitive().isString()) {
                    params.append("\"").append(strValue).append("\"");
                } else {
                    params.append(strValue);
                }
            } else {
                // For complex objects, just show the key
                params.append(key).append("=").append(value.toString());
            }
        }

        return params.toString();
    }

    /**
     * Execute tool via ToolRegistry. Tools manage their own transactions internally
     * if they mutate program state, avoiding EDT blocking and unnecessary read transactions.
     */
    private CompletableFuture<ToolResult> executeToolWithTransaction(String toolName, JsonObject arguments) {
        return toolRegistry.execute(toolName, arguments);
    }

    /**
     * Get the current conversation history.
     * Useful for persisting ReAct conversations.
     *
     * @return Copy of conversation history
     */
    public List<ChatMessage> getConversationHistory() {
        return new ArrayList<>(conversationHistory);
    }
}
