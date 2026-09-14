package ghidrassist.graphrag;

import ghidrassist.graphrag.nodes.KnowledgeNode;
import ghidrassist.graphrag.nodes.NodeType;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Locale;

/**
 * User-configurable scope for semantic summarization.
 */
public class SemanticAnalysisOptions {
    private final List<String> includeNamePatterns;
    private final List<String> excludeNamePatterns;
    private final List<AddressRange> includeRanges;
    private final List<AddressRange> excludeRanges;
    private final int maxNodes;
    private final boolean includeExternalNodes;

    public static SemanticAnalysisOptions defaults() {
        return new SemanticAnalysisOptions(
                Collections.emptyList(),
                Collections.emptyList(),
                Collections.emptyList(),
                Collections.emptyList(),
                0,
                false);
    }

    public SemanticAnalysisOptions(
            List<String> includeNamePatterns,
            List<String> excludeNamePatterns,
            List<AddressRange> includeRanges,
            List<AddressRange> excludeRanges,
            int maxNodes,
            boolean includeExternalNodes) {
        this.includeNamePatterns = normalizePatterns(includeNamePatterns);
        this.excludeNamePatterns = normalizePatterns(excludeNamePatterns);
        this.includeRanges = includeRanges != null ? new ArrayList<>(includeRanges) : Collections.emptyList();
        this.excludeRanges = excludeRanges != null ? new ArrayList<>(excludeRanges) : Collections.emptyList();
        this.maxNodes = Math.max(0, maxNodes);
        this.includeExternalNodes = includeExternalNodes;
    }

    public int getMaxNodes() {
        return maxNodes;
    }

    public boolean isDefaultScope() {
        return includeNamePatterns.isEmpty()
                && excludeNamePatterns.isEmpty()
                && includeRanges.isEmpty()
                && excludeRanges.isEmpty()
                && maxNodes == 0
                && !includeExternalNodes;
    }

    public boolean matches(KnowledgeNode node) {
        if (node == null) {
            return false;
        }
        if (!includeExternalNodes && node.getType() == NodeType.EXTERNAL) {
            return false;
        }

        String name = node.getName() != null
                ? node.getName().toLowerCase(Locale.ROOT)
                : "";
        Long address = node.getAddress();

        if (!includeNamePatterns.isEmpty() && includeNamePatterns.stream().noneMatch(name::contains)) {
            return false;
        }
        if (!includeRanges.isEmpty() && (address == null || includeRanges.stream().noneMatch(r -> r.contains(address)))) {
            return false;
        }
        if (!excludeNamePatterns.isEmpty() && excludeNamePatterns.stream().anyMatch(name::contains)) {
            return false;
        }
        if (address != null && !excludeRanges.isEmpty() && excludeRanges.stream().anyMatch(r -> r.contains(address))) {
            return false;
        }

        return true;
    }

    private static List<String> normalizePatterns(List<String> patterns) {
        if (patterns == null || patterns.isEmpty()) {
            return Collections.emptyList();
        }
        List<String> normalized = new ArrayList<>();
        for (String pattern : patterns) {
            if (pattern == null) {
                continue;
            }
            String trimmed = pattern.trim().toLowerCase(Locale.ROOT);
            if (!trimmed.isEmpty()) {
                normalized.add(trimmed);
            }
        }
        return normalized;
    }

    public static List<String> parsePatternList(String text) {
        if (text == null || text.isBlank()) {
            return Collections.emptyList();
        }
        List<String> values = new ArrayList<>();
        for (String part : text.split(",")) {
            String trimmed = part.trim();
            if (!trimmed.isEmpty()) {
                values.add(trimmed);
            }
        }
        return values;
    }

    public static List<AddressRange> parseRangeList(String text) {
        if (text == null || text.isBlank()) {
            return Collections.emptyList();
        }
        List<AddressRange> ranges = new ArrayList<>();
        for (String part : text.split(",")) {
            String trimmed = part.trim();
            if (trimmed.isEmpty()) {
                continue;
            }
            String[] pieces = trimmed.split("-", 2);
            long start = parseAddress(pieces[0].trim());
            long end = pieces.length == 2 ? parseAddress(pieces[1].trim()) : start;
            ranges.add(new AddressRange(Math.min(start, end), Math.max(start, end)));
        }
        return ranges;
    }

    private static long parseAddress(String text) {
        String value = text.trim();
        if (value.startsWith("0x") || value.startsWith("0X")) {
            value = value.substring(2);
        }
        return Long.parseUnsignedLong(value, 16);
    }

    public static class AddressRange {
        private final long start;
        private final long end;

        public AddressRange(long start, long end) {
            this.start = start;
            this.end = end;
        }

        public boolean contains(long address) {
            return Long.compareUnsigned(address, start) >= 0
                    && Long.compareUnsigned(address, end) <= 0;
        }
    }
}
