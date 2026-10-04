package ghidrassist.services;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.Swing;
import ghidra.util.task.Task;
import ghidra.util.task.TaskLauncher;
import ghidra.util.task.TaskMonitor;
import ghidrassist.AnalysisDB;
import ghidrassist.GhidrAssistPlugin;
import ghidrassist.LlmApi;
import ghidrassist.apiprovider.APIProviderConfig;
import ghidrassist.core.ActionExecutor;
import ghidrassist.core.ActionParser;
import ghidrassist.core.CodeUtils;
import ghidrassist.core.ActionConstants;

import javax.swing.table.DefaultTableModel;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Service for handling automated function analysis with actions.
 * Responsible for analyzing functions with AI tools and managing action execution.
 */
public class ActionAnalysisService {
    
    private final GhidrAssistPlugin plugin;
    private final AtomicInteger activeRequests;
    private final AtomicBoolean applyingActions = new AtomicBoolean(false);
    
    public ActionAnalysisService(GhidrAssistPlugin plugin) {
        this.plugin = plugin;
        this.activeRequests = new AtomicInteger(0);
    }
    
    /**
     * Create an action analysis request for a function
     */
    public ActionAnalysisRequest createAnalysisRequest(Function function, List<String> selectedActions) throws Exception {
        if (function == null) {
            throw new IllegalArgumentException("No function at current location.");
        }
        
        if (selectedActions.isEmpty()) {
            throw new IllegalArgumentException("No actions selected for analysis.");
        }
        
        String code = CodeUtils.getFunctionCode(function, TaskMonitor.DUMMY);
        if (code == null) {
            throw new Exception("Failed to get code from the current function.");
        }
        
        return new ActionAnalysisRequest(function, code, selectedActions);
    }
    
    /**
     * Execute action analysis requests
     */
    public void executeActionAnalysis(ActionAnalysisRequest request, ActionAnalysisHandler handler) throws Exception {
        APIProviderConfig config = GhidrAssistPlugin.getCurrentProviderConfig();
        if (config == null) {
            throw new Exception("No API provider configured.");
        }

        LlmApi llmApi = new LlmApi(config, plugin);

        // Apply saved reasoning config
        ghidra.program.model.listing.Program currentProgram = plugin.getCurrentProgram();
        if (currentProgram != null) {
            try {
                ghidrassist.AnalysisDB analysisDB = new ghidrassist.AnalysisDB();
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

        // Reset and set the active request counter
        activeRequests.set(request.getSelectedActions().size());
        
        for (String action : request.getSelectedActions()) {
            if (!handler.shouldContinue()) {
                break;
            }
            
            String actionPrompt = ActionConstants.ACTION_PROMPTS.get(action);
            if (actionPrompt != null) {
                String prompt = actionPrompt.replace("{code}", request.getCode());
                List<Map<String, Object>> functions = new ArrayList<>();
                functions.add(getActionFunction(action));
                
                llmApi.sendRequestAsyncWithFunctions(prompt, functions, 
                    createActionResponseHandler(action, handler));
            }
        }
    }
    
    /**
     * Apply selected actions from the analysis results.
     * Runs in a background task so the Swing thread stays responsive; table
     * updates are posted back to the Swing thread as each action finishes.
     */
    public void applyActions(DefaultTableModel model, Program program, Address address, AnalysisDB analysisDB) {
        if (program == null || address == null) {
            Msg.showWarn(this, null, "Apply Actions", "No program or address selected.");
            return;
        }

        // Snapshot the selected rows on the Swing thread
        List<PendingAction> pending = new ArrayList<>();
        for (int row = 0; row < model.getRowCount(); row++) {
            if (Boolean.TRUE.equals(model.getValueAt(row, 0))) {
                String action = model.getValueAt(row, 1).toString().replace(" ", "_");
                String argumentsJson = model.getValueAt(row, 4).toString();
                pending.add(new PendingAction(row, action, argumentsJson));
            }
        }
        if (pending.isEmpty() || !applyingActions.compareAndSet(false, true)) {
            return;
        }

        TaskLauncher.launch(new Task("Applying Actions", true, true, true) {
            @Override
            public void run(TaskMonitor monitor) {
                try {
                    applyPendingActions(pending, model, program, address, analysisDB, monitor);
                } finally {
                    applyingActions.set(false);
                }
            }
        });
    }

    private void applyPendingActions(List<PendingAction> pending, DefaultTableModel model, Program program,
            Address address, AnalysisDB analysisDB, TaskMonitor monitor) {
        monitor.initialize(pending.size());
        String binaryId = program.getExecutableSHA256();

        try (ActionExecutor.Session session = new ActionExecutor.Session(program, monitor)) {
            for (PendingAction p : pending) {
                if (monitor.isCancelled()) {
                    break;
                }
                monitor.setMessage("Applying " + p.action.replace("_", " "));

                String status;
                boolean applied;
                try {
                    // Pass the analysisDB so LLM renames are recorded for provenance tracking
                    ActionExecutor.executeAction(p.action, p.argumentsJson, program, address,
                            analysisDB, binaryId, session);
                    status = "Applied";
                    applied = true;
                } catch (Exception e) {
                    status = "Failed: " + e.getMessage();
                    applied = false;
                }

                String finalStatus = status;
                boolean finalApplied = applied;
                Swing.runLater(() -> {
                    if (p.row >= model.getRowCount()) {
                        return;
                    }
                    model.setValueAt(finalStatus, p.row, 3);
                    if (finalApplied) {
                        model.setValueAt(Boolean.FALSE, p.row, 0);
                    }
                });
                monitor.incrementProgress(1);
            }
        }
    }

    private record PendingAction(int row, String action, String argumentsJson) {}

    /**
     * Get the function template for a specific action
     */
    private Map<String, Object> getActionFunction(String actionName) {
        for (Map<String, Object> fnTemplate : ActionConstants.FN_TEMPLATES) {
            @SuppressWarnings("unchecked")
            Map<String, Object> functionMap = (Map<String, Object>) fnTemplate.get("function");
            if (functionMap.get("name").equals(actionName)) {
                return fnTemplate;
            }
        }
        return null;
    }
    
    /**
     * Create response handler for action analysis
     */
    private LlmApi.LlmResponseHandler createActionResponseHandler(String action, ActionAnalysisHandler handler) {
        return new LlmApi.LlmResponseHandler() {
            @Override
            public void onStart() {
                handler.onActionStart(action);
            }
            
            @Override
            public void onUpdate(String partialResponse) {
                // Function calls don't have partial updates
            }
            
            @Override
            public void onComplete(String fullResponse) {
                handler.onActionComplete(action, fullResponse);
                
                int remaining = activeRequests.decrementAndGet();
                if (remaining <= 0) {
                    activeRequests.set(0);
                    handler.onAllActionsComplete();
                }
            }
            
            @Override
            public void onError(Throwable error) {
                handler.onActionError(action, error);
                
                int remaining = activeRequests.decrementAndGet();
                if (remaining <= 0) {
                    activeRequests.set(0);
                    handler.onAllActionsComplete();
                }
            }
            
            @Override
            public boolean shouldContinue() {
                return handler.shouldContinue();
            }
        };
    }
    
    /**
     * Parse and display action results
     */
    public void parseAndDisplayActions(String response, DefaultTableModel tableModel) throws Exception {
        ActionParser.parseAndDisplay(response, tableModel);
    }
    
    /**
     * Check if analysis is currently running
     */
    public boolean isAnalysisRunning() {
        return activeRequests.get() > 0;
    }
    
    /**
     * Cancel all running analysis
     */
    public void cancelAnalysis() {
        activeRequests.set(0);
    }
    
    /**
     * Request object for action analysis operations
     */
    public static class ActionAnalysisRequest {
        private final Function function;
        private final String code;
        private final List<String> selectedActions;
        
        public ActionAnalysisRequest(Function function, String code, List<String> selectedActions) {
            this.function = function;
            this.code = code;
            this.selectedActions = new ArrayList<>(selectedActions);
        }
        
        public Function getFunction() { return function; }
        public String getCode() { return code; }
        public List<String> getSelectedActions() { return selectedActions; }
    }
    
    /**
     * Handler interface for action analysis callbacks
     */
    public interface ActionAnalysisHandler {
        void onActionStart(String action);
        void onActionComplete(String action, String response);
        void onActionError(String action, Throwable error);
        void onAllActionsComplete();
        boolean shouldContinue();
    }
}