package ghidrassist.tools.approval;

/**
 * Deterministic risk tiers for tool execution approval.
 */
public enum ToolRiskTier {
    READ_ONLY,
    MUTATING,
    EXTERNAL,
    UNKNOWN
}
