package ghidrassist.core;

import java.util.Arrays;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import com.google.gson.Gson;
import com.google.gson.JsonObject;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.decompiler.util.FillOutStructureHelper;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.InvalidDataTypeException;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.listing.Function.FunctionUpdateType;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighFunctionDBUtil;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.pcode.HighVariable;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.model.symbol.SymbolType;
import ghidra.program.model.symbol.SymbolUtilities;
import ghidra.util.Msg;
import ghidra.util.data.DataTypeParser;
import ghidrassist.AnalysisDB;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;

public class ActionExecutor {

    private static final Gson gson = new Gson();

    /**
     * Shared state for executing a batch of actions against one program.
     * Holds a single decompiler process (instead of spawning one per lookup) and
     * remembers which functions already had their local names committed.
     */
    public static final class Session implements AutoCloseable {
        private final Program program;
        private final TaskMonitor monitor;
        private final Set<Address> committedFunctions = new HashSet<>();
        private DecompInterface decompiler;

        public Session(Program program, TaskMonitor monitor) {
            this.program = program;
            this.monitor = monitor != null ? monitor : TaskMonitor.DUMMY;
        }

        DecompInterface getDecompiler() {
            if (decompiler == null) {
                decompiler = new DecompInterface();
                setupDecompiler(decompiler, program);
            }
            return decompiler;
        }

        DecompileResults decompile(Function function) {
            DecompInterface ifc = getDecompiler();
            // Earlier actions in the batch may have changed the program
            ifc.flushCache();
            return ifc.decompileFunction(function, 30, monitor);
        }

        /** Commit local names once per function; returns true if a commit happened now. */
        boolean ensureLocalsCommitted(Function function) {
            if (committedFunctions.contains(function.getEntryPoint())) {
                return false;
            }
            commitLocalNames(function, this);
            committedFunctions.add(function.getEntryPoint());
            return true;
        }

        @Override
        public void close() {
            if (decompiler != null) {
                decompiler.dispose();
                decompiler = null;
            }
        }
    }

    /**
     * Execute a specific action with the given arguments.
     * @param action The action to execute
     * @param argumentsJson JSON string containing action arguments
     * @param program The current program
     * @param address The current address
     * @throws Exception if action execution fails
     */
    public static void executeAction(String action, String argumentsJson, Program program, Address address) 
            throws Exception {
        try (Session session = new Session(program, TaskMonitor.DUMMY)) {
            executeAction(action, argumentsJson, program, address, null, null, session);
        }
    }

    /**
     * Execute an action and record LLM renames for provenance tracking.
     */
    public static void executeAction(String action, String argumentsJson, Program program, Address address,
                                     AnalysisDB analysisDB, String binaryId) throws Exception {
        try (Session session = new Session(program, TaskMonitor.DUMMY)) {
            executeAction(action, argumentsJson, program, address, analysisDB, binaryId, session);
        }
    }

    /**
     * Execute an action within a shared {@link Session}, recording LLM renames when
     * analysisDB and binaryId are provided.
     */
    public static void executeAction(String action, String argumentsJson, Program program, Address address,
                                     AnalysisDB analysisDB, String binaryId, Session session) throws Exception {
        JsonObject arguments = gson.fromJson(argumentsJson, JsonObject.class);

        int transaction = program.startTransaction("Execute " + action);
        boolean success = false;

        try {
            switch (action) {
                case "rename_function":
                    executeFunctionRename(arguments, program, address);
                    if (analysisDB != null && binaryId != null) {
                        String newName = arguments.get("new_name").getAsString().strip();
                        analysisDB.recordLlmRename(binaryId, address.getOffset(), "function", newName);
                    }
                    break;
                case "rename_variable":
                    executeVariableRename(arguments, program, address, session);
                    if (analysisDB != null && binaryId != null) {
                        String newName = arguments.get("new_name").getAsString().strip();
                        analysisDB.recordLlmRename(binaryId, address.getOffset(), "variable", newName);
                    }
                    break;
                case "retype_variable":
                    executeVariableRetype(arguments, program, address, session);
                    break;
                case "auto_create_struct":
                    executeAutoCreateStruct(arguments, program, address, session);
                    break;
                default:
                    throw new InvalidInputException("Unknown action: " + action);
            }
            success = true;
        } finally {
            program.endTransaction(transaction, success);
        }
    }

    private static void executeFunctionRename(JsonObject arguments, Program program, Address address)
            throws InvalidInputException, DuplicateNameException {
        String newName = arguments.get("new_name").getAsString().strip();
        Function function = getFunctionAtAddress(program, address);

        function.setName(newName, SourceType.USER_DEFINED);
    }

    private static void executeVariableRename(JsonObject arguments, Program program, Address address,
            Session session) throws InvalidInputException, DuplicateNameException {
        String varName = arguments.get("var_name").getAsString().strip();
        String newName = arguments.get("new_name").getAsString().strip();

        Function function = getFunctionAtAddress(program, address);
        Variable variable = findLocalVariable(function, varName, session);
        if (variable != null) {
            variable.setName(newName, SourceType.USER_DEFINED);
            return;
        }

        // Not a local/parameter: try globals (DAT_xxx, PTR_xxx, named data labels, ...)
        if (renameGlobal(program, function, varName, newName, session)) {
            return;
        }

        throw new InvalidInputException("Variable not found: " + varName);
    }

    /**
     * Rename a global symbol referenced by name. Handles default dynamic names (DAT_, PTR_, s_, ...)
     * which have no stored symbol, existing global labels, and globals known to the decompiler.
     */
    private static boolean renameGlobal(Program program, Function function, String varName, String newName,
            Session session) throws InvalidInputException, DuplicateNameException {
        SymbolTable symbolTable = program.getSymbolTable();

        // 1. Existing stored global symbol with this name
        for (Symbol sym : symbolTable.getGlobalSymbols(varName)) {
            SymbolType type = sym.getSymbolType();
            if (type == SymbolType.LABEL) {
                sym.setName(newName, SourceType.USER_DEFINED);
                return true;
            }
        }

        // 2. Default dynamic name, e.g. DAT_00401000 -> address 00401000
        Address globalAddr = SymbolUtilities.parseDynamicName(program.getAddressFactory(), varName);

        // 3. Ask the decompiler's global symbol map (covers names the decompiler shows)
        if (globalAddr == null) {
            DecompileResults res = session.decompile(function);
            if (res != null && res.decompileCompleted()) {
                var it = res.getHighFunction().getGlobalSymbolMap().getSymbols();
                while (it.hasNext()) {
                    HighSymbol hs = it.next();
                    if (varName.equals(hs.getName()) && hs.getStorage() != null
                            && hs.getStorage().getMinAddress() != null) {
                        globalAddr = hs.getStorage().getMinAddress();
                        break;
                    }
                }
            }
        }

        if (globalAddr == null) {
            return false;
        }

        Symbol primary = symbolTable.getPrimarySymbol(globalAddr);
        if (primary != null && !primary.isDynamic() && primary.getSymbolType() == SymbolType.LABEL) {
            primary.setName(newName, SourceType.USER_DEFINED);
        } else {
            Symbol created = symbolTable.createLabel(globalAddr, newName, SourceType.USER_DEFINED);
            created.setPrimary();
        }
        return true;
    }

    private static void executeVariableRetype(JsonObject arguments, Program program, Address address,
            Session session) throws Exception {
        String varName = arguments.get("var_name").getAsString().strip();
        String newTypeStr = arguments.get("new_type").getAsString().strip();
        
        Function function = getFunctionAtAddress(program, address);
        Variable variable = findVariable(function, varName, session);
        
        DataType newType = parseDataType(newTypeStr, program.getDataTypeManager(), program);
        if (newType == null) {
            throw new InvalidInputException("Failed to parse data type: " + newTypeStr);
        }
        
        variable.setDataType(newType, true, true, SourceType.USER_DEFINED);
    }

    private static void executeAutoCreateStruct(JsonObject arguments, Program program, Address address,
            Session session) throws Exception {
        String varName = arguments.get("var_name").getAsString().strip();
        Function function = getFunctionAtAddress(program, address);

        DecompileResults results = session.decompile(function);
        if (!results.decompileCompleted()) {
            throw new Exception("Decompilation failed for function: " + function.getName());
        }

        HighFunction highFunction = results.getHighFunction();
        HighVariable highVar = findHighVariable(highFunction, varName);

        if (highVar == null) {
            throw new InvalidInputException("Variable not found: " + varName);
        }

        createAndApplyStructure(program, function, highVar, session);
    }

    private static Function getFunctionAtAddress(Program program, Address address) 
            throws InvalidInputException {
        Function function = program.getFunctionManager().getFunctionContaining(address);
        if (function == null) {
            throw new InvalidInputException("No function at address: " + address);
        }
        return function;
    }

    private static Variable findVariable(Function function, String varName, Session session)
            throws InvalidInputException {
        Variable variable = findLocalVariable(function, varName, session);
        if (variable == null) {
            throw new InvalidInputException("Variable not found: " + varName);
        }
        return variable;
    }

    /** Find a local variable or parameter by name; returns null if not found. */
    private static Variable findLocalVariable(Function function, String varName, Session session) {
        // Commit local names to ensure all variables are available
        boolean freshlyCommitted = session.ensureLocalsCommitted(function);
        Variable variable = lookupVariable(function, varName);

        // An earlier action in the batch may have changed the decompiled locals; re-commit once
        if (variable == null && !freshlyCommitted) {
            commitLocalNames(function, session);
            variable = lookupVariable(function, varName);
        }
        return variable;
    }

    private static Variable lookupVariable(Function function, String varName) {
        // Search in all variables and parameters
        List<Variable> allVars = new ArrayList<>();
        allVars.addAll(Arrays.asList(function.getAllVariables()));
        allVars.addAll(Arrays.asList(function.getParameters()));

        for (Variable var : allVars) {
            if (var.getName().equals(varName)) {
                return var;
            }
        }
        return null;
    }

    private static DataType parseDataType(String typeStr, DataTypeManager dtm, Program program) 
            throws InvalidInputException, CancelledException, InvalidDataTypeException {
        // Try direct lookup first
        DataType dataType = dtm.getDataType(new CategoryPath("/"), typeStr);
        
        // If not found, try parsing
        if (dataType == null) {
            DataTypeParser parser = new DataTypeParser(dtm, program.getDataTypeManager(), null, DataTypeParser.AllowedDataTypes.ALL);
            dataType = parser.parse(typeStr);
        }
        
        return dataType;
    }

    private static void setupDecompiler(DecompInterface decompiler, Program program) {
        DecompileOptions options = new DecompileOptions();
        options.grabFromProgram(program);
        decompiler.setOptions(options);
        decompiler.openProgram(program);
    }

    private static HighVariable findHighVariable(HighFunction highFunction, String varName) {
        var symbols = highFunction.getLocalSymbolMap().getSymbols();
        while (symbols.hasNext()) {
            HighSymbol sym = symbols.next();
            if (sym.getName().equals(varName)) {
                return sym.getHighVariable();
            }
        }
        return null;
    }

    private static void createAndApplyStructure(Program program, Function function, 
            HighVariable highVar, Session session) throws Exception {
        
        FillOutStructureHelper fillHelper = new FillOutStructureHelper(program, session.monitor);
        Structure structDT = fillHelper.processStructure(highVar, function, false, true, session.getDecompiler());
        
        if (structDT == null) {
            throw new Exception("Failed to create structure");
        }

        // Add structure to data type manager
        DataTypeManager dtm = program.getDataTypeManager();
        structDT = (Structure) dtm.addDataType(structDT, DataTypeConflictHandler.DEFAULT_HANDLER);
        PointerDataType ptrStruct = new PointerDataType(structDT);

        // First get variable from function
        Variable var = findVariable(function, highVar.getSymbol().getName(), session);
        
        if (var instanceof ghidra.program.model.listing.AutoParameterImpl) {
            // Modify the function signature to change the data type of the auto-parameter
            updateFunctionParameter(function, var.getName(), ptrStruct);
        } else {
            // Update local variable
            HighFunctionDBUtil.updateDBVariable(highVar.getSymbol(), null, ptrStruct, SourceType.USER_DEFINED);
        }
    }

    private static void updateFunctionParameter(Function function, String paramName, 
            DataType newType) throws InvalidInputException, DuplicateNameException {
        
        Parameter[] parameters = function.getParameters();
        Parameter[] newParams = new Parameter[parameters.length];

        for (int i = 0; i < parameters.length; i++) {
            if (parameters[i].getName().equals(paramName)) {
                newParams[i] = new ghidra.program.model.listing.ParameterImpl(
                    parameters[i].getName(),
                    newType,
                    parameters[i].getVariableStorage(),
                    function.getProgram(),
                    SourceType.USER_DEFINED
                );
            } else {
                newParams[i] = parameters[i];
            }
        }

        function.updateFunction(
            function.getCallingConventionName(),
            null, // Keep return type
            FunctionUpdateType.CUSTOM_STORAGE,
            true,
            SourceType.USER_DEFINED,
            newParams
        );
    }

    /**
     * Commits local variable names to the database for a function
     */
    public static void commitLocalNames(Program program, Function function) {
        try (Session session = new Session(program, TaskMonitor.DUMMY)) {
            commitLocalNames(function, session);
        }
    }

    private static void commitLocalNames(Function function, Session session) {
        DecompileResults res = session.decompile(function);
        if (res.decompileCompleted()) {
            try {
                function.setName(function.getName(), SourceType.USER_DEFINED); // Commit the function parameters
                HighFunction hf = res.getHighFunction();
                HighFunctionDBUtil.commitLocalNamesToDatabase(hf, SourceType.ANALYSIS);
                HighFunctionDBUtil.commitParamsToDatabase(hf, true, null, SourceType.ANALYSIS);
            } catch (Exception e) {
                Msg.error(ActionExecutor.class, "Error committing local names: " + e.getMessage());
            }
        }
    }
}
