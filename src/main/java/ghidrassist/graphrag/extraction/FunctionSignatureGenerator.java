package ghidrassist.graphrag.extraction;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.regex.Pattern;

/**
 * Canonical masked-prefix signature generator shared across plugins.
 */
public class FunctionSignatureGenerator {

    private static final int MAX_INSTRUCTIONS_TO_SCAN = 200;
    private static final int MAX_SIGNATURE_BYTES = 64;
    private static final Pattern IDA_HEX_IMMEDIATE = Pattern.compile("\\b[0-9a-f]+h\\b");

    private final Program program;
    @SuppressWarnings("unused")
    private final TaskMonitor monitor;

    public FunctionSignatureGenerator(Program program, TaskMonitor monitor) {
        this.program = program;
        this.monitor = monitor;
    }

    public String generate(Function function) {
        if (function == null || function.isExternal()) {
            return null;
        }

        try {
            Instruction startInsn = program.getListing().getInstructionContaining(function.getEntryPoint());
            if (startInsn == null) {
                return null;
            }

            List<String> tokens = new ArrayList<>();
            List<Instruction> instructions = getInstructionsFrom(
                function.getBody(),
                startInsn.getMinAddress(),
                MAX_INSTRUCTIONS_TO_SCAN
            );

            for (Instruction instruction : instructions) {
                String[] masked = maskInstruction(instruction);
                for (String token : masked) {
                    tokens.add(token);
                    if (tokens.size() >= MAX_SIGNATURE_BYTES) {
                        return joinTokens(trimTrailingWildcards(tokens));
                    }
                }
            }

            return joinTokens(trimTrailingWildcards(tokens));
        } catch (Exception e) {
            return null;
        }
    }

    private String[] maskInstruction(Instruction instruction) throws Exception {
        byte[] bytes = instruction.getBytes();
        String[] tokens = new String[bytes.length];
        for (int i = 0; i < bytes.length; i++) {
            tokens[i] = String.format("%02X", bytes[i]);
        }

        String text = instruction.toString().toLowerCase(Locale.ROOT);
        String[] parts = text.split("\\s+", 2);
        String mnemonic = parts.length > 0 ? parts[0] : "";
        String operandText = parts.length > 1 ? parts[1] : "";

        if (isBranchLike(mnemonic)) {
            for (int i = 1; i < tokens.length; i++) {
                tokens[i] = "?";
            }
            return tokens;
        }

        if (shouldMaskOperands(operandText) && tokens.length > 1) {
            int start = Math.max(1, tokens.length - Math.min(4, tokens.length - 1));
            for (int i = start; i < tokens.length; i++) {
                tokens[i] = "?";
            }
        }

        return tokens;
    }

    private boolean isBranchLike(String mnemonic) {
        return mnemonic.startsWith("j") ||
               mnemonic.startsWith("call") ||
               mnemonic.startsWith("b") ||
               mnemonic.equals("loop") ||
               mnemonic.equals("loopne") ||
               mnemonic.equals("loope");
    }

    private boolean shouldMaskOperands(String operandText) {
        String[] markers = {
            "rip",
            " ptr ",
            "[",
            "got",
            "plt",
            "extern",
            "extrn",
            "offset",
            "off_",
            "sub_",
            "loc_",
            "data_",
            "cs:",
            "ds:",
            "0x"
        };
        for (String marker : markers) {
            if (operandText.contains(marker)) {
                return true;
            }
        }
        return IDA_HEX_IMMEDIATE.matcher(operandText).find();
    }

    private List<Instruction> getInstructionsFrom(
            AddressSetView body,
            Address startAddress,
            int maxInstructions
    ) {
        List<Instruction> instructions = new ArrayList<>();
        InstructionIterator iterator = program.getListing().getInstructions(startAddress, true);
        int count = 0;

        while (iterator.hasNext() && count < maxInstructions) {
            Instruction instruction = iterator.next();
            if (!body.contains(instruction.getMinAddress())) {
                break;
            }
            instructions.add(instruction);
            count++;
        }

        return instructions;
    }

    private List<String> trimTrailingWildcards(List<String> tokens) {
        List<String> trimmed = new ArrayList<>(tokens);
        while (!trimmed.isEmpty() && "?".equals(trimmed.get(trimmed.size() - 1))) {
            trimmed.remove(trimmed.size() - 1);
        }
        return trimmed;
    }

    private String joinTokens(List<String> tokens) {
        if (tokens.isEmpty()) {
            return null;
        }
        return String.join(" ", tokens);
    }
}
