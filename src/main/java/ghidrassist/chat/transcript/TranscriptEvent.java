package ghidrassist.chat.transcript;

import java.sql.Timestamp;

/**
 * Immutable transcript event used for rendering and persistence.
 */
public class TranscriptEvent {
    private final long id;
    private final int sessionId;
    private final String programHash;
    private final String correlationId;
    private final Long parentEventId;
    private final TranscriptEventKind kind;
    private final String role;
    private final String title;
    private final String contentText;
    private final String previewText;
    private final String metadataJson;
    private final String artifactId;
    private final Integer sourceMessageId;
    private final Integer sourceMessageOrder;
    private final Timestamp createdAt;

    public TranscriptEvent(long id, int sessionId, String programHash, String correlationId,
                           Long parentEventId, TranscriptEventKind kind, String role, String title,
                           String contentText, String previewText, String metadataJson,
                           String artifactId, Integer sourceMessageId, Integer sourceMessageOrder,
                           Timestamp createdAt) {
        this.id = id;
        this.sessionId = sessionId;
        this.programHash = programHash;
        this.correlationId = correlationId;
        this.parentEventId = parentEventId;
        this.kind = kind;
        this.role = role;
        this.title = title;
        this.contentText = contentText;
        this.previewText = previewText;
        this.metadataJson = metadataJson;
        this.artifactId = artifactId;
        this.sourceMessageId = sourceMessageId;
        this.sourceMessageOrder = sourceMessageOrder;
        this.createdAt = createdAt;
    }

    public long getId() {
        return id;
    }

    public int getSessionId() {
        return sessionId;
    }

    public String getProgramHash() {
        return programHash;
    }

    public String getCorrelationId() {
        return correlationId;
    }

    public Long getParentEventId() {
        return parentEventId;
    }

    public TranscriptEventKind getKind() {
        return kind;
    }

    public String getRole() {
        return role;
    }

    public String getTitle() {
        return title;
    }

    public String getContentText() {
        return contentText;
    }

    public String getPreviewText() {
        return previewText;
    }

    public String getMetadataJson() {
        return metadataJson;
    }

    public String getArtifactId() {
        return artifactId;
    }

    public Integer getSourceMessageId() {
        return sourceMessageId;
    }

    public Integer getSourceMessageOrder() {
        return sourceMessageOrder;
    }

    public Timestamp getCreatedAt() {
        return createdAt;
    }
}
