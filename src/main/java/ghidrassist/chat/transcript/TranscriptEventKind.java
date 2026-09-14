package ghidrassist.chat.transcript;

/**
 * First-class event kinds for the unified transcript timeline.
 */
public enum TranscriptEventKind {
    USER_MESSAGE("user_message"),
    ASSISTANT_MESSAGE("assistant_message"),
    TOOL_CALL_REQUESTED("tool_call_requested"),
    TOOL_CALL_STARTED("tool_call_started"),
    TOOL_CALL_COMPLETED("tool_call_completed"),
    TOOL_CALL_FAILED("tool_call_failed"),
    APPROVAL_REQUESTED("approval_requested"),
    APPROVAL_DECISION("approval_decision"),
    TODO_UPDATED("todo_updated"),
    FINDING_ADDED("finding_added"),
    ITERATION_NOTICE("iteration_notice"),
    CONTEXT_COMPACTED("context_compacted"),
    SYSTEM_NOTICE("system_notice"),
    DOCUMENT_SNAPSHOT("document_snapshot");

    private final String dbValue;

    TranscriptEventKind(String dbValue) {
        this.dbValue = dbValue;
    }

    public String getDbValue() {
        return dbValue;
    }

    public static TranscriptEventKind fromDbValue(String value) {
        for (TranscriptEventKind kind : values()) {
            if (kind.dbValue.equalsIgnoreCase(value)) {
                return kind;
            }
        }
        return SYSTEM_NOTICE;
    }
}
