package ghidrassist.tools.registry;

import com.google.gson.JsonObject;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidrassist.tools.api.Tool;
import ghidrassist.tools.api.ToolExecutor;
import ghidrassist.tools.api.ToolProvider;
import ghidrassist.tools.api.ToolResult;
import ghidrassist.tools.native_.NativeToolManager;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

/**
 * Central registry that aggregates tools from all providers.
 * Provides unified access to tools regardless of their source.
 *
 * Usage:
 *   ToolRegistry registry = new ToolRegistry();
 *   registry.registerProvider(new NativeToolManager(db));
 *   registry.registerProvider(new MCPToolManager(mcpRegistry));
 *
 *   List<Tool> allTools = registry.getAllTools();
 *   ToolResult result = registry.execute("get_semantic_analysis", args).join();
 */
public class ToolRegistry implements ToolExecutor {

    private static final int DEFAULT_MAX_FUNCTION_TOOLS = 120;
    private static final Pattern QUERY_TOKEN_PATTERN = Pattern.compile("[a-z0-9_]+");

    private final List<ToolProvider> providers = new ArrayList<>();
    private Program currentProgram;
    private Address currentAddress;

    /**
     * Register a tool provider.
     * @param provider The provider to register
     */
    public void registerProvider(ToolProvider provider) {
        if (provider != null) {
            providers.add(provider);
            // Set current program context if we have one
            if (currentProgram != null) {
                provider.setContext(currentProgram);
            }
            Msg.info(this, "Registered tool provider: " + provider.getProviderName() +
                    " with " + provider.getTools().size() + " tools");
        }
    }

    /**
     * Unregister a tool provider.
     * @param provider The provider to unregister
     */
    public void unregisterProvider(ToolProvider provider) {
        providers.remove(provider);
    }

    /**
     * Check if a provider with the given name is already registered.
     * @param providerName Name of the provider
     * @return true if a provider with this name is registered
     */
    public boolean hasProvider(String providerName) {
        return providers.stream().anyMatch(p -> p.getProviderName().equals(providerName));
    }

    /**
     * Get all registered providers.
     * @return List of providers
     */
    public List<ToolProvider> getProviders() {
        return new ArrayList<>(providers);
    }

    @Override
    public List<Tool> getAllTools() {
        return providers.stream()
                .flatMap(p -> p.getTools().stream())
                .collect(Collectors.toList());
    }

    /**
     * Get tools from a specific provider.
     * @param providerName Name of the provider
     * @return List of tools from that provider
     */
    public List<Tool> getToolsByProvider(String providerName) {
        return providers.stream()
                .filter(p -> p.getProviderName().equals(providerName))
                .flatMap(p -> p.getTools().stream())
                .collect(Collectors.toList());
    }

    /**
     * Find a tool by name across all providers.
     * @param toolName Tool name
     * @return The tool, or null if not found
     */
    public Tool getTool(String toolName) {
        for (ToolProvider provider : providers) {
            for (Tool tool : provider.getTools()) {
                if (tool.getName().equals(toolName)) {
                    return tool;
                }
            }
        }
        return null;
    }

    /**
     * Check if any provider handles the given tool.
     * @param toolName Tool name
     * @return true if a provider can handle the tool
     */
    public boolean handlesTool(String toolName) {
        return providers.stream().anyMatch(p -> p.handlesTool(toolName));
    }

    @Override
    public CompletableFuture<ToolResult> execute(String toolName, JsonObject args) {
        for (ToolProvider provider : providers) {
            if (provider.handlesTool(toolName)) {
                Msg.debug(this, "Routing tool '" + toolName + "' to provider: " + provider.getProviderName());
                return provider.executeTool(toolName, args);
            }
        }

        Msg.warn(this, "No provider found for tool: " + toolName);
        return CompletableFuture.completedFuture(
                ToolResult.error("Unknown tool: " + toolName));
    }

    /**
     * Set the Ghidra program context for all providers.
     * @param program Current Ghidra program
     */
    public void setContext(Program program) {
        this.currentProgram = program;
        for (ToolProvider provider : providers) {
            provider.setContext(program);
            // Also set address if we have one
            if (currentAddress != null && provider instanceof NativeToolManager) {
                ((NativeToolManager) provider).setAddress(currentAddress);
            }
        }
        Msg.debug(this, "Updated program context for " + providers.size() + " providers");
    }

    /**
     * Set the current address context for tools that need it.
     * @param address Current cursor address in Ghidra
     */
    public void setAddress(Address address) {
        this.currentAddress = address;
        for (ToolProvider provider : providers) {
            if (provider instanceof NativeToolManager) {
                ((NativeToolManager) provider).setAddress(address);
            }
        }
        Msg.debug(this, "Updated address context: " + (address != null ? address.toString() : "null"));
    }

    /**
     * Set both program and address context.
     * @param program Current Ghidra program
     * @param address Current cursor address
     */
    public void setFullContext(Program program, Address address) {
        this.currentProgram = program;
        this.currentAddress = address;
        for (ToolProvider provider : providers) {
            provider.setContext(program);
            if (provider instanceof NativeToolManager) {
                ((NativeToolManager) provider).setFullContext(program, address);
            }
        }
        Msg.debug(this, "Updated full context for " + providers.size() + " providers");
    }

    /**
     * Get the current program context.
     * @return Current program or null
     */
    public Program getCurrentProgram() {
        return currentProgram;
    }

    /**
     * Get the current address context.
     * @return Current address or null
     */
    public Address getCurrentAddress() {
        return currentAddress;
    }

    /**
     * Get tool count summary.
     * @return Summary string
     */
    public String getSummary() {
        StringBuilder sb = new StringBuilder();
        sb.append("ToolRegistry: ").append(getAllTools().size()).append(" total tools\n");
        for (ToolProvider provider : providers) {
            sb.append("  - ").append(provider.getProviderName())
              .append(": ").append(provider.getTools().size()).append(" tools\n");
        }
        return sb.toString();
    }

    /**
     * Get all tools as function definitions for LLM function calling.
     * This converts Tool objects to the Map format expected by LLM providers.
     * Deduplicates tools by name (first registration wins).
     * @return List of function definitions
     */
    public List<Map<String, Object>> getToolsAsFunction() {
        return getToolsAsFunction(null, Integer.MAX_VALUE);
    }

    /**
     * Get a query-aware, capped list of tools as function definitions for LLM function calling.
     * This keeps tool payloads under provider limits while prioritizing tools relevant to the query.
     *
     * @param queryContext The current user query or analysis objective.
     * @return List of function definitions ordered by relevance.
     */
    public List<Map<String, Object>> getToolsAsFunction(String queryContext) {
        return getToolsAsFunction(queryContext, DEFAULT_MAX_FUNCTION_TOOLS);
    }

    /**
     * Get a query-aware, capped list of tools as function definitions for LLM function calling.
     *
     * @param queryContext The current user query or analysis objective.
     * @param maxTools Maximum number of tool definitions to include.
     * @return List of function definitions ordered by relevance.
     */
    public List<Map<String, Object>> getToolsAsFunction(String queryContext, int maxTools) {
        Map<String, Tool> uniqueTools = new LinkedHashMap<>();
        for (Tool tool : getAllTools()) {
            if (!uniqueTools.containsKey(tool.getName())) {
                uniqueTools.put(tool.getName(), tool);
            } else {
                Msg.debug(this, "Skipping duplicate tool: " + tool.getName() +
                        " (already registered from another provider)");
            }
        }

        if (maxTools <= 0) {
            maxTools = DEFAULT_MAX_FUNCTION_TOOLS;
        }

        if (queryContext == null || queryContext.trim().isEmpty()) {
            return uniqueTools.values().stream()
                    .limit(maxTools)
                    .map(this::toolToFunctionSchema)
                    .collect(Collectors.toList());
        }

        List<String> queryTokens = tokenizeQuery(queryContext);

        return uniqueTools.values().stream()
                .map(tool -> new ScoredTool(tool, scoreTool(tool, queryTokens)))
                .sorted(Comparator
                        .comparingInt(ScoredTool::score).reversed()
                        .thenComparing(scored -> scored.tool().getName(), String.CASE_INSENSITIVE_ORDER))
                .limit(maxTools)
                .map(scored -> toolToFunctionSchema(scored.tool()))
                .collect(Collectors.toList());
    }

    private List<String> tokenizeQuery(String queryContext) {
        List<String> tokens = new ArrayList<>();
        Matcher matcher = QUERY_TOKEN_PATTERN.matcher(queryContext.toLowerCase());
        while (matcher.find()) {
            String token = matcher.group();
            if (token.length() >= 2) {
                tokens.add(token);
            }
        }
        return tokens;
    }

    private int scoreTool(Tool tool, List<String> queryTokens) {
        String name = tool.getName().toLowerCase();
        String description = tool.getDescription() != null ? tool.getDescription().toLowerCase() : "";

        int score = 0;

        // Strongly prefer semantic inspection and code analysis tools for reverse engineering prompts.
        if (name.contains("semantic") || name.contains("decompile") || name.contains("disassemble") ||
                name.contains("code") || name.contains("function") || name.contains("address") ||
                name.contains("data") || name.contains("xref") || name.contains("string") ||
                name.contains("import") || name.contains("export") || name.contains("block") ||
                name.contains("comment") || name.contains("variable") || name.contains("type") ||
                name.contains("analysis") || name.contains("search") || name.contains("program")) {
            score += 20;
        }

        for (String token : queryTokens) {
            if (name.equals(token)) {
                score += 100;
            } else if (name.contains(token)) {
                score += 50;
            }

            if (description.contains(token)) {
                score += 15;
            }
        }

        return score;
    }

    private static final class ScoredTool {
        private final Tool tool;
        private final int score;

        private ScoredTool(Tool tool, int score) {
            this.tool = tool;
            this.score = score;
        }

        private Tool tool() {
            return tool;
        }

        private int score() {
            return score;
        }
    }

    /**
     * Convert a Tool to function calling schema format.
     */
    private Map<String, Object> toolToFunctionSchema(Tool tool) {
        Map<String, Object> function = new HashMap<>();
        function.put("type", "function");

        Map<String, Object> functionDef = new HashMap<>();
        functionDef.put("name", tool.getName());
        functionDef.put("description", tool.getDescription());

        // Convert JsonObject to Map for parameters
        JsonObject inputSchema = tool.getInputSchema();
        if (inputSchema != null) {
            functionDef.put("parameters", jsonObjectToMap(inputSchema));
        } else {
            // Default empty parameters
            Map<String, Object> emptyParams = new HashMap<>();
            emptyParams.put("type", "object");
            emptyParams.put("properties", new HashMap<>());
            functionDef.put("parameters", emptyParams);
        }

        function.put("function", functionDef);
        return function;
    }

    /**
     * Convert JsonObject to Map for function schema.
     */
    private Map<String, Object> jsonObjectToMap(JsonObject json) {
        Map<String, Object> map = new HashMap<>();
        for (String key : json.keySet()) {
            map.put(key, jsonElementToObject(json.get(key)));
        }
        return map;
    }

    /**
     * Convert JsonElement to appropriate Java object.
     */
    private Object jsonElementToObject(com.google.gson.JsonElement element) {
        if (element == null || element.isJsonNull()) {
            return null;
        } else if (element.isJsonPrimitive()) {
            com.google.gson.JsonPrimitive primitive = element.getAsJsonPrimitive();
            if (primitive.isBoolean()) {
                return primitive.getAsBoolean();
            } else if (primitive.isNumber()) {
                return primitive.getAsNumber();
            } else {
                return primitive.getAsString();
            }
        } else if (element.isJsonArray()) {
            List<Object> list = new ArrayList<>();
            for (com.google.gson.JsonElement e : element.getAsJsonArray()) {
                list.add(jsonElementToObject(e));
            }
            return list;
        } else if (element.isJsonObject()) {
            return jsonObjectToMap(element.getAsJsonObject());
        }
        return element.toString();
    }
}
