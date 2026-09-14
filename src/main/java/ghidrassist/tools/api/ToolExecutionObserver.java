package ghidrassist.tools.api;

import com.google.gson.JsonObject;

/**
 * Observer for structured tool execution lifecycle events.
 */
public interface ToolExecutionObserver {
    void onToolCallRequested(int sessionId, String programHash, String correlationId, Tool tool, JsonObject args);

    void onToolCallStarted(int sessionId, String programHash, String correlationId, Tool tool, JsonObject args);

    void onToolCallCompleted(int sessionId, String programHash, String correlationId,
                             Tool tool, JsonObject args, ToolResult result);

    void onToolCallFailed(int sessionId, String programHash, String correlationId,
                          Tool tool, JsonObject args, String errorMessage);
}
