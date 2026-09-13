package ghidrassist.tools.registry;

import com.google.gson.JsonObject;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidrassist.tools.approval.ToolApprovalService;
import ghidrassist.tools.api.Tool;
import ghidrassist.tools.api.ToolExecutionObserver;
import ghidrassist.tools.api.ToolExecutor;
import ghidrassist.tools.api.ToolProvider;
import ghidrassist.tools.api.ToolResult;
import ghidrassist.tools.native_.NativeToolManager;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.function.IntSupplier;
import java.util.function.Supplier;
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

    private final List<ToolProvider> providers = new ArrayList<>();
    private Program currentProgram;
    private Address currentAddress;
    private volatile ToolExecutionObserver executionObserver;
    private volatile ToolApprovalService approvalService;
    private volatile IntSupplier activeSessionSupplier = () -> -1;
    private volatile Supplier<String> programHashSupplier = () -> null;

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
            // Msg.info(this, "Registered tool provider: " + provider.getProviderName() +" with " + provider.getTools().size() + " tools");
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
        Tool tool = getTool(toolName);
        if (tool == null) {
            Msg.warn(this, "No provider found for tool: " + toolName);
            return CompletableFuture.completedFuture(
                    ToolResult.error("Unknown tool: " + toolName));
        }

        int sessionId = activeSessionSupplier != null ? activeSessionSupplier.getAsInt() : -1;
        String programHash = programHashSupplier != null ? programHashSupplier.get() : null;
        String correlationId = java.util.UUID.randomUUID().toString();

        if (executionObserver != null && sessionId > 0) {
            executionObserver.onToolCallRequested(sessionId, programHash, correlationId, tool, args);
        }
        // Msg.info(this, "Tool requested: " + toolName + " (" + tool.getSource() + ")");

        CompletableFuture<ToolApprovalService.ApprovalOutcome> approvalFuture =
            approvalService != null
                ? approvalService.requestApproval(sessionId, programHash, correlationId, tool, args)
                : CompletableFuture.completedFuture(ToolApprovalService.ApprovalOutcome.approved(
                    ToolApprovalService.DECISION_ALLOW_ONCE));

        return approvalFuture.thenComposeAsync(outcome -> {
            if (outcome == null || !outcome.isApproved()) {
                Msg.warn(this, "Tool denied: " + toolName);
                if (executionObserver != null && sessionId > 0) {
                    executionObserver.onToolCallFailed(sessionId, programHash, correlationId, tool, args,
                            "Execution denied by user");
                }
                return CompletableFuture.completedFuture(ToolResult.error("Tool execution denied by user"));
            }

            for (ToolProvider provider : providers) {
                if (provider.handlesTool(toolName)) {
                    // Msg.debug(this, "Routing tool '" + toolName + "' to provider: " + provider.getProviderName());
                    // Msg.info(this, "Executing tool '" + toolName + "' via provider " + provider.getProviderName());
                    if (executionObserver != null && sessionId > 0) {
                        executionObserver.onToolCallStarted(sessionId, programHash, correlationId, tool, args);
                    }
                    return provider.executeTool(toolName, args)
                            .handle((result, throwable) -> {
                                if (throwable != null) {
                                    Msg.warn(this, "Tool failed: " + toolName + " - " + throwable.getMessage());
                                    if (executionObserver != null && sessionId > 0) {
                                        executionObserver.onToolCallFailed(sessionId, programHash, correlationId,
                                                tool, args, throwable.getMessage());
                                    }
                                    return ToolResult.error(throwable.getMessage());
                                }

                                ToolResult safeResult = result != null ? result : ToolResult.error("Tool returned no result");
                                if (safeResult.isError()) {
                                    Msg.warn(this, "Tool returned error: " + toolName + " - " + safeResult.getErrorMessage());
                                } else {
                                    // Msg.info(this, "Tool completed: " + toolName);
                                }
                                if (executionObserver != null && sessionId > 0) {
                                    if (safeResult.isError()) {
                                        executionObserver.onToolCallFailed(sessionId, programHash, correlationId,
                                                tool, args, safeResult.getErrorMessage());
                                    } else {
                                        executionObserver.onToolCallCompleted(sessionId, programHash, correlationId,
                                                tool, args, safeResult);
                                    }
                                }
                                return safeResult;
                            });
                }
            }

            Msg.warn(this, "No provider found for tool: " + toolName);
            return CompletableFuture.completedFuture(ToolResult.error("Unknown tool: " + toolName));
        });
    }

    public void setExecutionObserver(ToolExecutionObserver executionObserver) {
        this.executionObserver = executionObserver;
    }

    public void setApprovalService(ToolApprovalService approvalService) {
        this.approvalService = approvalService;
    }

    public void setActiveSessionSupplier(IntSupplier activeSessionSupplier) {
        this.activeSessionSupplier = activeSessionSupplier != null ? activeSessionSupplier : () -> -1;
    }

    public void setProgramHashSupplier(Supplier<String> programHashSupplier) {
        this.programHashSupplier = programHashSupplier != null ? programHashSupplier : () -> null;
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
        // Msg.debug(this, "Updated program context for " + providers.size() + " providers");
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
        // Msg.debug(this, "Updated address context: " + (address != null ? address.toString() : "null"));
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
        // Msg.debug(this, "Updated full context for " + providers.size() + " providers");
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
        // Deduplicate by tool name - first registration wins
        Map<String, Tool> uniqueTools = new java.util.LinkedHashMap<>();
        for (Tool tool : getAllTools()) {
            if (!uniqueTools.containsKey(tool.getName())) {
                uniqueTools.put(tool.getName(), tool);
            } else {
                Msg.debug(this, "Skipping duplicate tool: " + tool.getName() + " (already registered from another provider)");
            }
        }

        return uniqueTools.values().stream()
                .map(this::toolToFunctionSchema)
                .collect(Collectors.toList());
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
