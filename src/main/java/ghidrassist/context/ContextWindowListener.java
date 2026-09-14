package ghidrassist.context;

/**
 * Listener for context-window status and compaction events.
 */
public interface ContextWindowListener {
    void onStatusUpdated(ContextStatus status);

    void onContextCompacted(String summary, int originalMessageCount, int finalMessageCount);
}
