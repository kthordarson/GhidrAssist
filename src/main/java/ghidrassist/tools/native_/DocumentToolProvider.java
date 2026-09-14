package ghidrassist.tools.native_;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidrassist.tools.api.Tool;
import ghidrassist.tools.api.ToolProvider;
import ghidrassist.tools.api.ToolResult;

import java.util.Collections;
import java.util.List;
import java.util.concurrent.CompletableFuture;

/**
 * Tool provider for creating document chats.
 * Provides a single tool "ga_add_document" that creates a new chat session
 * populated with custom markdown content. Used by the ReAct agent to output
 * clean reports and as groundwork for SymGraph document sync.
 */
public class DocumentToolProvider implements ToolProvider {

    private static final String PROVIDER_NAME = "Document";
    private static final String TOOL_NAME = "ga_add_document";

    private DocumentChatHandler handler;

    /**
     * Callback interface for creating document chats.
     * Implemented by the component that manages chat sessions.
     */
    public interface DocumentChatHandler {
        /**
         * Create a new chat session with the given title and content.
         *
         * @param title   Title for the new chat document
         * @param content Markdown content for the document
         * @return The new session ID
         */
        int createDocumentChat(String title, String content);
    }

    /**
     * Set the handler for document chat creation.
     *
     * @param handler The handler to use
     */
    public void setHandler(DocumentChatHandler handler) {
        this.handler = handler;
    }

    @Override
    public String getProviderName() {
        return PROVIDER_NAME;
    }

    @Override
    public List<Tool> getTools() {
        // Build the JSON schema for the tool
        JsonObject schema = new JsonObject();
        schema.addProperty("type", "object");

        JsonObject properties = new JsonObject();

        JsonObject titleProp = new JsonObject();
        titleProp.addProperty("type", "string");
        titleProp.addProperty("description", "Title for the new chat document");
        properties.add("title", titleProp);

        JsonObject contentProp = new JsonObject();
        contentProp.addProperty("type", "string");
        contentProp.addProperty("description", "Markdown content for the document");
        properties.add("content", contentProp);

        schema.add("properties", properties);

        JsonArray required = new JsonArray();
        required.add("title");
        required.add("content");
        schema.add("required", required);

        NativeTool tool = new NativeTool(
                TOOL_NAME,
                "Create a new chat document with custom markdown content. " +
                "Use this to produce standalone analysis reports, summaries, " +
                "or findings separate from the current conversation.",
                schema,
                PROVIDER_NAME
        );

        return Collections.singletonList(tool);
    }

    @Override
    public CompletableFuture<ToolResult> executeTool(String name, JsonObject args) {
        if (!TOOL_NAME.equals(name)) {
            return CompletableFuture.completedFuture(
                    ToolResult.error("Unknown document tool: " + name));
        }

        if (handler == null) {
            return CompletableFuture.completedFuture(
                    ToolResult.error("Document chat handler not registered"));
        }

        return CompletableFuture.supplyAsync(() -> {
            try {
                String title = args.has("title") ? args.get("title").getAsString() : "Untitled Document";
                String content = args.has("content") ? args.get("content").getAsString() : "";

                int chatId = handler.createDocumentChat(title, content);
                return ToolResult.success("Document '" + title + "' created as Chat " + chatId);
            } catch (Exception e) {
                Msg.error(this, "Document chat creation failed: " + e.getMessage(), e);
                return ToolResult.error("Error creating document: " + e.getMessage());
            }
        });
    }

    @Override
    public boolean handlesTool(String name) {
        return TOOL_NAME.equals(name);
    }

    @Override
    public void setContext(Program program) {
        // Document tool does not need program context
    }
}
