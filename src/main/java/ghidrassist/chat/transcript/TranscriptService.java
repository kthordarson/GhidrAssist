package ghidrassist.chat.transcript;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import ghidra.util.Msg;
import ghidrassist.agent.react.TodoListManager;
import ghidrassist.chat.PersistedChatMessage;
import ghidrassist.tools.api.Tool;
import ghidrassist.tools.api.ToolExecutionObserver;
import ghidrassist.tools.api.ToolResult;

import java.nio.file.Path;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Consumer;

/**
 * Append-only transcript service used for persistence, backfill, and rendering.
 */
public class TranscriptService implements ToolExecutionObserver {
    public static class ReActContinuationBridge {
        private final String reactRunId;
        private final String markdown;
        private final int findingCount;
        private final int pendingCount;
        private final String status;

        public ReActContinuationBridge(String reactRunId, String markdown, int findingCount,
                                       int pendingCount, String status) {
            this.reactRunId = reactRunId;
            this.markdown = markdown;
            this.findingCount = findingCount;
            this.pendingCount = pendingCount;
            this.status = status;
        }

        public String getReactRunId() {
            return reactRunId;
        }

        public String getMarkdown() {
            return markdown;
        }

        public int getFindingCount() {
            return findingCount;
        }

        public int getPendingCount() {
            return pendingCount;
        }

        public String getStatus() {
            return status;
        }
    }

    private static class ActiveReActRun {
        private final String reactRunId;
        private final String objective;

        private ActiveReActRun(String reactRunId, String objective) {
            this.reactRunId = reactRunId;
            this.objective = objective;
        }
    }

    private final Connection connection;
    private final TranscriptArtifactStore artifactStore;
    private final TranscriptRenderer renderer;
    private final Map<Integer, ActiveReActRun> activeReActRuns = new ConcurrentHashMap<>();
    private volatile Consumer<Integer> sessionUpdateListener;

    public TranscriptService(Connection connection, Path artifactRoot) {
        this.connection = connection;
        this.artifactStore = new TranscriptArtifactStore(artifactRoot);
        this.renderer = new TranscriptRenderer();
    }

    public synchronized boolean hasEvents(int sessionId) {
        String sql = "SELECT 1 FROM GHChatTranscriptEvents WHERE session_id = ? LIMIT 1";
        try (PreparedStatement stmt = connection.prepareStatement(sql)) {
            stmt.setInt(1, sessionId);
            return stmt.executeQuery().next();
        } catch (SQLException e) {
            Msg.warn(this, "Failed to check transcript presence: " + e.getMessage());
            return false;
        }
    }

    public synchronized void ensureBackfilledFromMessages(String programHash, int sessionId,
                                                          List<PersistedChatMessage> messages) {
        if (sessionId <= 0 || messages == null || messages.isEmpty()) {
            return;
        }
        List<TranscriptEvent> existingEvents = loadEvents(sessionId);
        List<TranscriptEvent> conversationalEvents = filterConversationalEvents(existingEvents);
        int searchStart = 0;
        for (PersistedChatMessage message : messages) {
            TranscriptEventKind kind = switch (message.getRole()) {
                case "user" -> TranscriptEventKind.USER_MESSAGE;
                case "assistant" -> TranscriptEventKind.ASSISTANT_MESSAGE;
                case "error" -> TranscriptEventKind.SYSTEM_NOTICE;
                case "tool_call", "tool_response" -> TranscriptEventKind.TOOL_CALL_COMPLETED;
                default -> TranscriptEventKind.SYSTEM_NOTICE;
            };
            String title = switch (kind) {
                case USER_MESSAGE -> "User";
                case ASSISTANT_MESSAGE -> "Assistant";
                case TOOL_CALL_COMPLETED -> "Legacy Tool Activity";
                case SYSTEM_NOTICE -> "Legacy Event";
                default -> kind.getDbValue();
            };
            int matchedIndex = findBestConversationEventMatch(
                conversationalEvents, searchStart, kind, message.getContent(), message.getTimestamp(),
                message.getDbId(), message.getOrder());
            if (matchedIndex >= 0) {
                TranscriptEvent matchedEvent = conversationalEvents.get(matchedIndex);
                if (matchedEvent.getSourceMessageId() == null || matchedEvent.getSourceMessageOrder() == null) {
                    updateEventSourceLink(matchedEvent.getId(), message.getDbId(), message.getOrder());
                    conversationalEvents.set(matchedIndex, new TranscriptEvent(
                        matchedEvent.getId(),
                        matchedEvent.getSessionId(),
                        matchedEvent.getProgramHash(),
                        matchedEvent.getCorrelationId(),
                        matchedEvent.getParentEventId(),
                        matchedEvent.getKind(),
                        matchedEvent.getRole(),
                        matchedEvent.getTitle(),
                        matchedEvent.getContentText(),
                        matchedEvent.getPreviewText(),
                        matchedEvent.getMetadataJson(),
                        matchedEvent.getArtifactId(),
                        message.getDbId(),
                        message.getOrder(),
                        matchedEvent.getCreatedAt()
                    ));
                    Msg.info(this, "Linked transcript event " + matchedEvent.getId()
                        + " to message " + message.getDbId() + " (order=" + message.getOrder() + ")");
                }
                removeLaterSourceLinkedDuplicates(sessionId, conversationalEvents, matchedIndex,
                    kind, message.getContent(), message.getDbId(), message.getOrder());
                searchStart = matchedIndex + 1;
                continue;
            }
            appendEvent(sessionId, programHash, null, null, kind, message.getRole(), title,
                message.getContent(), message.getContent(), message.getNativeMessageData(),
                null, message.getDbId(), message.getOrder(), message.getTimestamp(), false);
            TranscriptEvent appendedEvent = new TranscriptEvent(
                -1L,
                sessionId,
                programHash,
                null,
                null,
                kind,
                message.getRole(),
                title,
                message.getContent(),
                message.getContent(),
                message.getNativeMessageData(),
                null,
                message.getDbId(),
                message.getOrder(),
                message.getTimestamp()
            );
            existingEvents.add(appendedEvent);
            conversationalEvents.add(appendedEvent);
            searchStart = conversationalEvents.size();
        }
    }

    public synchronized void ensureBackfilledFromReActMessages(String programHash, int sessionId,
                                                               List<ghidrassist.apiprovider.ChatMessage> messages) {
        if (sessionId <= 0 || hasEvents(sessionId) || messages == null || messages.isEmpty()) {
            return;
        }
        for (ghidrassist.apiprovider.ChatMessage message : messages) {
            TranscriptEventKind kind = "user".equals(message.getRole())
                ? TranscriptEventKind.USER_MESSAGE
                : TranscriptEventKind.ASSISTANT_MESSAGE;
            String title = kind == TranscriptEventKind.USER_MESSAGE ? "User" : "Assistant";
            appendEvent(sessionId, programHash, null, null, kind, message.getRole(), title,
                message.getContent(), message.getContent(), null, null, null, null, null, false);
        }
    }

    public void appendUserMessage(int sessionId, String programHash, String content, Timestamp createdAt) {
        appendUserMessage(sessionId, programHash, content, createdAt, null, null);
    }

    public void appendUserMessage(int sessionId, String programHash, String content, Timestamp createdAt,
                                  Integer sourceMessageId, Integer sourceMessageOrder) {
        appendEvent(sessionId, programHash, null, null, TranscriptEventKind.USER_MESSAGE,
            "user", "User", content, content, null, null, sourceMessageId, sourceMessageOrder, createdAt, true);
    }

    public void appendAssistantMessage(int sessionId, String programHash, String content, Timestamp createdAt) {
        appendAssistantMessage(sessionId, programHash, content, createdAt, null, null);
    }

    public void appendAssistantMessage(int sessionId, String programHash, String content, Timestamp createdAt,
                                       Integer sourceMessageId, Integer sourceMessageOrder) {
        appendEvent(sessionId, programHash, null, null, TranscriptEventKind.ASSISTANT_MESSAGE,
            "assistant", "Assistant", content, content, mergeActiveReActMetadata(sessionId, null),
            null, sourceMessageId, sourceMessageOrder, createdAt, true);
    }

    public void appendReActAssistantMessage(int sessionId, String programHash, String content, Timestamp createdAt,
                                            String reactRunId, String objective, String status) {
        appendEvent(sessionId, programHash, null, null, TranscriptEventKind.ASSISTANT_MESSAGE,
            "assistant", "Assistant", content, content,
            buildReActAssistantMetadata(reactRunId, objective, status),
            null, null, null, createdAt, true);
    }

    public void appendSystemNotice(int sessionId, String programHash, String title, String content) {
        appendEvent(sessionId, programHash, null, null, TranscriptEventKind.SYSTEM_NOTICE,
            "system", title, content, content, null, null, null, null, null, true);
    }

    public void appendDocumentSnapshot(int sessionId, String programHash, String title, String content) {
        appendEvent(sessionId, programHash, null, null, TranscriptEventKind.DOCUMENT_SNAPSHOT,
            "assistant", title, content, content, null, null, null, null, null, true);
    }

    public void appendContextCompacted(int sessionId, String programHash, String summary) {
        appendContextCompacted(sessionId, programHash, summary, null);
    }

    public void appendContextCompacted(int sessionId, String programHash, String summary, String metadataJson) {
        appendEvent(sessionId, programHash, null, null, TranscriptEventKind.CONTEXT_COMPACTED,
            "system", "Conversation summarized for context budget", summary, summary, metadataJson, null, null, null, null, true);
    }

    public void appendApprovalRequested(int sessionId, String programHash, String correlationId, String requestId,
                                        String toolName, String toolSource, String riskTier, JsonObject args) {
        appendEvent(sessionId, programHash, correlationId, null, TranscriptEventKind.APPROVAL_REQUESTED,
            "system", "Approval required: " + toolName,
            args != null ? args.toString() : "{}", args != null ? args.toString() : "{}",
            buildApprovalRequestedMetadata(sessionId, requestId, toolName, toolSource, riskTier, args),
            null, null, null, null, true);
    }

    public void appendApprovalDecision(int sessionId, String programHash, String correlationId, String requestId,
                                       String toolName, String decision, String riskTier, String scope,
                                       String toolSource) {
        appendEvent(sessionId, programHash, correlationId, null, TranscriptEventKind.APPROVAL_DECISION,
            "system", "Approval decision: " + toolName,
            decision, decision,
            buildApprovalDecisionMetadata(sessionId, requestId, toolName, toolSource, riskTier, decision, scope),
            null, null, null, null, true);
    }

    public void appendTodoSnapshot(int sessionId, String programHash, String summary,
                                   List<TodoListManager.Todo> todos, Integer iteration) {
        appendTodoSnapshot(sessionId, programHash, summary, todos, iteration, null, null);
    }

    public void appendTodoSnapshot(int sessionId, String programHash, String summary,
                                   List<TodoListManager.Todo> todos, Integer iteration,
                                   String reactRunId, String objective) {
        appendEvent(sessionId, programHash, null, null, TranscriptEventKind.TODO_UPDATED,
            "system", "Investigation Tasks", summary, summary,
            buildTodoMetadata(summary, todos, iteration, reactRunId, objective),
            null, null, null, null, true);
    }

    public void appendFinding(int sessionId, String programHash, String finding, Integer iteration) {
        appendFinding(sessionId, programHash, finding, iteration, null);
    }

    public void appendFinding(int sessionId, String programHash, String finding, Integer iteration,
                              String reactRunId) {
        appendEvent(sessionId, programHash, null, null, TranscriptEventKind.FINDING_ADDED,
            "assistant", "Finding", finding, finding,
            buildFindingMetadata(iteration, reactRunId), null, null, null, null, true);
    }

    public void appendIterationNotice(int sessionId, String programHash, String title, String content,
                                      Integer iteration, String category) {
        appendIterationNotice(sessionId, programHash, title, content, iteration, category, null, null);
    }

    public void appendIterationNotice(int sessionId, String programHash, String title, String content,
                                      Integer iteration, String category, String reactRunId, String objective) {
        appendEvent(sessionId, programHash, null, null, TranscriptEventKind.ITERATION_NOTICE,
            "system", title, content, content,
            buildIterationNoticeMetadata(iteration, category, reactRunId, objective),
            null, null, null, null, true);
    }

    public void beginReActRun(int sessionId, String reactRunId, String objective) {
        if (sessionId <= 0 || reactRunId == null || reactRunId.isBlank()) {
            return;
        }
        activeReActRuns.put(sessionId, new ActiveReActRun(reactRunId, objective));
    }

    public void endReActRun(int sessionId, String reactRunId) {
        if (sessionId <= 0) {
            return;
        }
        ActiveReActRun active = activeReActRuns.get(sessionId);
        if (active == null) {
            return;
        }
        if (reactRunId == null || reactRunId.equals(active.reactRunId)) {
            activeReActRuns.remove(sessionId);
        }
    }

    public synchronized String renderSessionHtml(int sessionId) {
        return renderer.renderDocument(loadEvents(sessionId));
    }

    public synchronized String renderSessionHtmlFragment(int sessionId) {
        return renderer.renderFragment(loadEvents(sessionId));
    }

    public synchronized String renderStreamingAssistantCardPrefix(Timestamp timestamp) {
        return renderer.renderStreamingAssistantCardPrefix(timestamp);
    }

    public synchronized String renderStreamingAssistantCardSuffix() {
        return renderer.renderStreamingAssistantCardSuffix();
    }

    public synchronized void toggleToolGroupExpansion(String correlationId) {
        renderer.toggleToolGroup(correlationId);
    }

    public synchronized void toggleTodoCard(long eventId) {
        renderer.toggleTodoCard(eventId);
    }

    public synchronized ReActContinuationBridge buildLatestReActContinuationBridge(int sessionId) {
        if (sessionId <= 0) {
            return null;
        }

        List<TranscriptEvent> events = loadEvents(sessionId);
        if (events.isEmpty()) {
            return null;
        }

        TranscriptEvent finalEvent = null;
        JsonObject finalMetadata = null;
        for (int i = events.size() - 1; i >= 0; i--) {
            TranscriptEvent event = events.get(i);
            if (event.getKind() != TranscriptEventKind.ASSISTANT_MESSAGE) {
                continue;
            }
            JsonObject metadata = parseMetadata(event.getMetadataJson());
            if (metadata != null && metadata.has("react_final") && metadata.get("react_final").getAsBoolean()) {
                finalEvent = event;
                finalMetadata = metadata;
                break;
            }
        }

        if (finalEvent == null || finalMetadata == null) {
            return null;
        }

        String reactRunId = getMetadataString(finalMetadata, "react_run_id");
        if (reactRunId == null || reactRunId.isBlank()) {
            return null;
        }

        String objective = getMetadataString(finalMetadata, "react_objective");
        String status = getMetadataString(finalMetadata, "react_status");
        List<String> findings = new ArrayList<>();
        LinkedHashSet<String> findingSet = new LinkedHashSet<>();
        JsonObject latestTodoMetadata = null;

        for (TranscriptEvent event : events) {
            JsonObject metadata = parseMetadata(event.getMetadataJson());
            if (!reactRunId.equals(getMetadataString(metadata, "react_run_id"))) {
                continue;
            }
            if (event.getKind() == TranscriptEventKind.FINDING_ADDED) {
                String finding = normalizeBridgeText(event.getContentText(), 320);
                if (!finding.isBlank() && findingSet.add(finding)) {
                    findings.add(finding);
                }
            } else if (event.getKind() == TranscriptEventKind.TODO_UPDATED) {
                latestTodoMetadata = metadata;
            }
        }

        if (findings.size() > 6) {
            findings = findings.subList(Math.max(0, findings.size() - 6), findings.size());
        }

        int pendingCount = getMetadataInt(latestTodoMetadata, "pending_count");
        int activeCount = getMetadataInt(latestTodoMetadata, "in_progress_count");
        String activeTodo = extractActiveTodo(latestTodoMetadata);

        StringBuilder markdown = new StringBuilder();
        markdown.append("## Prior ReAct Investigation Context\n\n");
        if (objective != null && !objective.isBlank()) {
            markdown.append("- Objective: ").append(objective.trim()).append("\n");
        }
        if (status != null && !status.isBlank()) {
            markdown.append("- Status: ").append(status.trim()).append("\n");
        }

        String finalAnswer = normalizeBridgeText(finalEvent.getContentText(), 900);
        if (!finalAnswer.isBlank()) {
            markdown.append("\nConclusion:\n").append(finalAnswer).append("\n");
        }

        if (!findings.isEmpty()) {
            markdown.append("\nKey findings:\n");
            for (String finding : findings) {
                markdown.append("- ").append(finding).append("\n");
            }
        }

        if ((activeCount > 0 || pendingCount > 0) && activeTodo != null && !activeTodo.isBlank()) {
            markdown.append("\nOpen investigation items:\n");
            markdown.append("- ").append(activeTodo).append("\n");
        }

        return new ReActContinuationBridge(
            reactRunId,
            markdown.toString().trim(),
            findings.size(),
            pendingCount,
            status
        );
    }

    public synchronized boolean updateAssistantMessageBySource(int sessionId, Integer sourceMessageId,
                                                               Integer sourceMessageOrder, String newContent) {
        if (sessionId <= 0 || (sourceMessageId == null && sourceMessageOrder == null)) {
            return false;
        }
        String sql = """
            UPDATE GHChatTranscriptEvents
            SET content_text = ?, preview_text = ?, artifact_id = NULL
            WHERE id = (
                SELECT id FROM GHChatTranscriptEvents
                WHERE session_id = ? AND event_kind = ? AND (
                    (? IS NOT NULL AND source_message_id = ?)
                    OR (? IS NOT NULL AND source_message_order = ?)
                )
                ORDER BY id DESC
                LIMIT 1
            )
        """;
        try (PreparedStatement stmt = connection.prepareStatement(sql)) {
            stmt.setString(1, newContent);
            stmt.setString(2, newContent);
            stmt.setInt(3, sessionId);
            stmt.setString(4, TranscriptEventKind.ASSISTANT_MESSAGE.getDbValue());
            if (sourceMessageId != null) {
                stmt.setInt(5, sourceMessageId);
                stmt.setInt(6, sourceMessageId);
            } else {
                stmt.setNull(5, java.sql.Types.INTEGER);
                stmt.setNull(6, java.sql.Types.INTEGER);
            }
            if (sourceMessageOrder != null) {
                stmt.setInt(7, sourceMessageOrder);
                stmt.setInt(8, sourceMessageOrder);
            } else {
                stmt.setNull(7, java.sql.Types.INTEGER);
                stmt.setNull(8, java.sql.Types.INTEGER);
            }
            boolean updated = stmt.executeUpdate() > 0;
            if (updated) {
                touchSession(sessionId);
                notifySessionUpdated(sessionId);
            }
            return updated;
        } catch (SQLException e) {
            Msg.warn(this, "Failed to update assistant transcript event by source: " + e.getMessage());
            return false;
        }
    }

    public synchronized boolean updateLatestAssistantMessage(int sessionId, String newContent) {
        if (sessionId <= 0) {
            return false;
        }
        String sql = """
            UPDATE GHChatTranscriptEvents
            SET content_text = ?, preview_text = ?, artifact_id = NULL
            WHERE id = (
                SELECT id FROM GHChatTranscriptEvents
                WHERE session_id = ? AND event_kind = ?
                ORDER BY id DESC
                LIMIT 1
            )
        """;
        try (PreparedStatement stmt = connection.prepareStatement(sql)) {
            stmt.setString(1, newContent);
            stmt.setString(2, newContent);
            stmt.setInt(3, sessionId);
            stmt.setString(4, TranscriptEventKind.ASSISTANT_MESSAGE.getDbValue());
            boolean updated = stmt.executeUpdate() > 0;
            if (updated) {
                touchSession(sessionId);
                notifySessionUpdated(sessionId);
            }
            return updated;
        } catch (SQLException e) {
            Msg.warn(this, "Failed to update latest assistant transcript event: " + e.getMessage());
            return false;
        }
    }

    public synchronized List<TranscriptEvent> loadEvents(int sessionId) {
        List<TranscriptEvent> events = new ArrayList<>();
        String sql = """
            SELECT id, session_id, program_hash, correlation_id, parent_event_id, event_kind, role,
                   title, content_text, preview_text, metadata_json, artifact_id,
                   source_message_id, source_message_order, created_at
            FROM GHChatTranscriptEvents
            WHERE session_id = ?
            ORDER BY id ASC
        """;
        try (PreparedStatement stmt = connection.prepareStatement(sql)) {
            stmt.setInt(1, sessionId);
            ResultSet rs = stmt.executeQuery();
            while (rs.next()) {
                long parentEventId = rs.getLong("parent_event_id");
                events.add(new TranscriptEvent(
                    rs.getLong("id"),
                    rs.getInt("session_id"),
                    rs.getString("program_hash"),
                    rs.getString("correlation_id"),
                    rs.wasNull() ? null : parentEventId,
                    TranscriptEventKind.fromDbValue(rs.getString("event_kind")),
                    rs.getString("role"),
                    rs.getString("title"),
                    rs.getString("content_text"),
                    rs.getString("preview_text"),
                    rs.getString("metadata_json"),
                    rs.getString("artifact_id"),
                    getNullableInt(rs, "source_message_id"),
                    getNullableInt(rs, "source_message_order"),
                    rs.getTimestamp("created_at")
                ));
            }
        } catch (SQLException e) {
            Msg.error(this, "Failed to load transcript events: " + e.getMessage());
        }
        return events;
    }

    public void setSessionUpdateListener(Consumer<Integer> sessionUpdateListener) {
        this.sessionUpdateListener = sessionUpdateListener;
    }

    @Override
    public void onToolCallRequested(int sessionId, String programHash, String correlationId,
                                    Tool tool, JsonObject args) {
        appendEvent(sessionId, programHash, correlationId, null, TranscriptEventKind.TOOL_CALL_REQUESTED,
            "tool", tool.getName(), args != null ? args.toString() : "{}",
            args != null ? args.toString() : "{}",
            buildToolMetadata(sessionId, tool, args), null, null, null, null, true);
    }

    @Override
    public void onToolCallStarted(int sessionId, String programHash, String correlationId,
                                  Tool tool, JsonObject args) {
        Long parentId = findMostRecentEventId(sessionId, correlationId, TranscriptEventKind.TOOL_CALL_REQUESTED);
        appendEvent(sessionId, programHash, correlationId, parentId, TranscriptEventKind.TOOL_CALL_STARTED,
            "tool", tool.getName(), "Executing...", "Executing...",
            buildToolMetadata(sessionId, tool, args), null, null, null, null, true);
    }

    @Override
    public void onToolCallCompleted(int sessionId, String programHash, String correlationId,
                                    Tool tool, JsonObject args, ToolResult result) {
        TranscriptArtifactStore.StoredArtifact artifact =
            artifactStore.maybeStore(sessionId, "tool_result", result != null ? result.getContentOrError() : "");
        Long parentId = findMostRecentEventId(sessionId, correlationId, TranscriptEventKind.TOOL_CALL_STARTED);
        long eventId = appendEvent(sessionId, programHash, correlationId, parentId,
            TranscriptEventKind.TOOL_CALL_COMPLETED, "tool", tool.getName(),
            artifact.getInlineContent(), artifact.getPreviewText(),
            buildToolMetadata(sessionId, tool, args), artifact.getArtifactId(), null, null, null, true);
        if (artifact.getArtifactId() != null) {
            persistArtifact(eventId, sessionId, artifact);
        }
    }

    @Override
    public void onToolCallFailed(int sessionId, String programHash, String correlationId,
                                 Tool tool, JsonObject args, String errorMessage) {
        Long parentId = findMostRecentEventId(sessionId, correlationId, TranscriptEventKind.TOOL_CALL_STARTED);
        appendEvent(sessionId, programHash, correlationId, parentId, TranscriptEventKind.TOOL_CALL_FAILED,
            "tool", tool.getName(), errorMessage, errorMessage,
            buildToolMetadata(sessionId, tool, args), null, null, null, null, true);
    }

    private synchronized long appendEvent(int sessionId, String programHash, String correlationId,
                                          Long parentEventId, TranscriptEventKind kind, String role,
                                          String title, String contentText, String previewText,
                                          String metadataJson, String artifactId,
                                          Integer sourceMessageId, Integer sourceMessageOrder,
                                          Timestamp createdAt, boolean touchSession) {
        String sql = """
            INSERT INTO GHChatTranscriptEvents (
                session_id, program_hash, correlation_id, parent_event_id, event_kind, role, title,
                content_text, preview_text, metadata_json, artifact_id,
                source_message_id, source_message_order, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, COALESCE(?, CURRENT_TIMESTAMP))
        """;
        try (PreparedStatement stmt = connection.prepareStatement(sql, Statement.RETURN_GENERATED_KEYS)) {
            stmt.setInt(1, sessionId);
            stmt.setString(2, programHash);
            stmt.setString(3, correlationId);
            if (parentEventId != null) {
                stmt.setLong(4, parentEventId);
            } else {
                stmt.setNull(4, java.sql.Types.INTEGER);
            }
            stmt.setString(5, kind.getDbValue());
            stmt.setString(6, role);
            stmt.setString(7, title);
            stmt.setString(8, contentText);
            stmt.setString(9, previewText);
            stmt.setString(10, metadataJson);
            stmt.setString(11, artifactId);
            if (sourceMessageId != null) {
                stmt.setInt(12, sourceMessageId);
            } else {
                stmt.setNull(12, java.sql.Types.INTEGER);
            }
            if (sourceMessageOrder != null) {
                stmt.setInt(13, sourceMessageOrder);
            } else {
                stmt.setNull(13, java.sql.Types.INTEGER);
            }
            stmt.setTimestamp(14, createdAt);
            stmt.executeUpdate();

            if (touchSession) {
                touchSession(sessionId);
            }
            notifySessionUpdated(sessionId);

            ResultSet keys = stmt.getGeneratedKeys();
            if (keys.next()) {
                return keys.getLong(1);
            }
        } catch (SQLException e) {
            Msg.error(this, "Failed to append transcript event: " + e.getMessage());
        }
        return -1;
    }

    private void notifySessionUpdated(int sessionId) {
        Consumer<Integer> listener = sessionUpdateListener;
        if (listener != null) {
            listener.accept(sessionId);
        }
    }

    private synchronized void persistArtifact(long eventId, int sessionId,
                                              TranscriptArtifactStore.StoredArtifact artifact) {
        String sql = """
            INSERT OR REPLACE INTO GHChatArtifacts (
                artifact_id, session_id, event_id, artifact_type, storage_path, preview_text, byte_size
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
        """;
        try (PreparedStatement stmt = connection.prepareStatement(sql)) {
            stmt.setString(1, artifact.getArtifactId());
            stmt.setInt(2, sessionId);
            stmt.setLong(3, eventId);
            stmt.setString(4, artifact.getArtifactType());
            stmt.setString(5, artifact.getStoragePath());
            stmt.setString(6, artifact.getPreviewText());
            stmt.setInt(7, artifact.getByteSize());
            stmt.executeUpdate();
        } catch (SQLException e) {
            Msg.warn(this, "Failed to persist artifact metadata: " + e.getMessage());
        }
    }

    private synchronized Long findMostRecentEventId(int sessionId, String correlationId, TranscriptEventKind kind) {
        String sql = """
            SELECT id FROM GHChatTranscriptEvents
            WHERE session_id = ? AND correlation_id = ? AND event_kind = ?
            ORDER BY id DESC LIMIT 1
        """;
        try (PreparedStatement stmt = connection.prepareStatement(sql)) {
            stmt.setInt(1, sessionId);
            stmt.setString(2, correlationId);
            stmt.setString(3, kind.getDbValue());
            ResultSet rs = stmt.executeQuery();
            if (rs.next()) {
                return rs.getLong("id");
            }
        } catch (SQLException e) {
            Msg.warn(this, "Failed to resolve parent transcript event: " + e.getMessage());
        }
        return null;
    }

    private List<TranscriptEvent> filterConversationalEvents(List<TranscriptEvent> events) {
        List<TranscriptEvent> filtered = new ArrayList<>();
        if (events == null || events.isEmpty()) {
            return filtered;
        }
        for (TranscriptEvent event : events) {
            if (event == null || event.getKind() == null) {
                continue;
            }
            switch (event.getKind()) {
                case USER_MESSAGE, ASSISTANT_MESSAGE, SYSTEM_NOTICE, TOOL_CALL_COMPLETED -> filtered.add(event);
                default -> {
                }
            }
        }
        return filtered;
    }

    private int findBestConversationEventMatch(List<TranscriptEvent> events, int startIndex,
                                               TranscriptEventKind kind, String content, Timestamp timestamp,
                                               Integer sourceMessageId, Integer sourceMessageOrder) {
        int sourceMatchedIndex = findMatchingConversationEventBySource(
            events, startIndex, kind, sourceMessageId, sourceMessageOrder);
        int unlinkedTimestampMatch = findMatchingConversationEventUnlinked(
            events, startIndex, kind, content, timestamp, true);
        if (unlinkedTimestampMatch >= 0 &&
            (sourceMatchedIndex < 0 || unlinkedTimestampMatch < sourceMatchedIndex)) {
            return unlinkedTimestampMatch;
        }
        int unlinkedContentMatch = findMatchingConversationEventUnlinked(
            events, startIndex, kind, content, timestamp, false);
        if (unlinkedContentMatch >= 0 &&
            (sourceMatchedIndex < 0 || unlinkedContentMatch < sourceMatchedIndex)) {
            return unlinkedContentMatch;
        }
        if (sourceMatchedIndex >= 0) {
            return sourceMatchedIndex;
        }
        return findMatchingConversationEvent(events, startIndex, kind, content, timestamp);
    }

    private int findMatchingConversationEvent(List<TranscriptEvent> events, int startIndex,
                                              TranscriptEventKind kind, String content, Timestamp timestamp) {
        if (events == null || events.isEmpty()) {
            return -1;
        }
        int safeStart = Math.max(0, startIndex);
        String normalizedContent = content != null ? content.trim() : "";
        for (int i = safeStart; i < events.size(); i++) {
            TranscriptEvent event = events.get(i);
            if (!eventMatches(event, kind, normalizedContent, timestamp, true)) {
                continue;
            }
            return i;
        }
        for (int i = safeStart; i < events.size(); i++) {
            TranscriptEvent event = events.get(i);
            if (!eventMatches(event, kind, normalizedContent, timestamp, false)) {
                continue;
            }
            return i;
        }
        return -1;
    }

    private int findMatchingConversationEventUnlinked(List<TranscriptEvent> events, int startIndex,
                                                      TranscriptEventKind kind, String content, Timestamp timestamp,
                                                      boolean requireTimestampMatch) {
        if (events == null || events.isEmpty()) {
            return -1;
        }
        int safeStart = Math.max(0, startIndex);
        String normalizedContent = content != null ? content.trim() : "";
        for (int i = safeStart; i < events.size(); i++) {
            TranscriptEvent event = events.get(i);
            if (event == null || event.getKind() != kind) {
                continue;
            }
            if (event.getSourceMessageId() != null || event.getSourceMessageOrder() != null) {
                continue;
            }
            if (!eventMatches(event, kind, normalizedContent, timestamp, requireTimestampMatch)) {
                continue;
            }
            return i;
        }
        return -1;
    }

    private int findMatchingConversationEventBySource(List<TranscriptEvent> events, int startIndex,
                                                      TranscriptEventKind kind, Integer sourceMessageId,
                                                      Integer sourceMessageOrder) {
        if (events == null || events.isEmpty()) {
            return -1;
        }
        int safeStart = Math.max(0, startIndex);
        for (int i = safeStart; i < events.size(); i++) {
            TranscriptEvent event = events.get(i);
            if (event == null || event.getKind() != kind) {
                continue;
            }
            if (sourceMessageId != null && sourceMessageId.equals(event.getSourceMessageId())) {
                return i;
            }
            if (sourceMessageOrder != null && sourceMessageOrder.equals(event.getSourceMessageOrder())) {
                return i;
            }
        }
        return -1;
    }

    private void updateEventSourceLink(long eventId, Integer sourceMessageId, Integer sourceMessageOrder) {
        if (eventId <= 0 || (sourceMessageId == null && sourceMessageOrder == null)) {
            return;
        }
        String sql = """
            UPDATE GHChatTranscriptEvents
            SET source_message_id = COALESCE(source_message_id, ?),
                source_message_order = COALESCE(source_message_order, ?)
            WHERE id = ?
        """;
        try (PreparedStatement stmt = connection.prepareStatement(sql)) {
            if (sourceMessageId != null) {
                stmt.setInt(1, sourceMessageId);
            } else {
                stmt.setNull(1, java.sql.Types.INTEGER);
            }
            if (sourceMessageOrder != null) {
                stmt.setInt(2, sourceMessageOrder);
            } else {
                stmt.setNull(2, java.sql.Types.INTEGER);
            }
            stmt.setLong(3, eventId);
            stmt.executeUpdate();
        } catch (SQLException e) {
            Msg.warn(this, "Failed to update transcript/source message link: " + e.getMessage());
        }
    }

    private void removeLaterSourceLinkedDuplicates(int sessionId, List<TranscriptEvent> events, int canonicalIndex,
                                                   TranscriptEventKind kind, String content,
                                                   Integer sourceMessageId, Integer sourceMessageOrder) {
        if (events == null || events.isEmpty() || canonicalIndex < 0 || canonicalIndex >= events.size()) {
            return;
        }
        if (sourceMessageId == null && sourceMessageOrder == null) {
            return;
        }

        TranscriptEvent canonical = events.get(canonicalIndex);
        String normalizedContent = content != null ? content.trim() : "";
        for (int i = events.size() - 1; i > canonicalIndex; i--) {
            TranscriptEvent event = events.get(i);
            if (event == null || event.getKind() != kind) {
                continue;
            }
            String eventContent = event.getContentText() != null ? event.getContentText().trim() : "";
            if (!eventContent.equals(normalizedContent)) {
                continue;
            }
            boolean sameSource = (sourceMessageId != null && sourceMessageId.equals(event.getSourceMessageId()))
                || (sourceMessageOrder != null && sourceMessageOrder.equals(event.getSourceMessageOrder()));
            if (!sameSource || event.getId() == canonical.getId()) {
                continue;
            }
            deleteEvent(event.getId());
            events.remove(i);
            Msg.info(this, "Removed duplicate transcript event " + event.getId()
                + " for message " + sourceMessageId + " in session " + sessionId);
        }
    }

    private Integer getNullableInt(ResultSet rs, String columnName) throws SQLException {
        int value = rs.getInt(columnName);
        return rs.wasNull() ? null : value;
    }

    private boolean eventMatches(TranscriptEvent event, TranscriptEventKind kind, String normalizedContent,
                                 Timestamp timestamp, boolean requireTimestampMatch) {
        if (event == null || event.getKind() != kind) {
            return false;
        }
        String eventContent = event.getContentText() != null ? event.getContentText().trim() : "";
        if (!eventContent.equals(normalizedContent)) {
            return false;
        }
        return !requireTimestampMatch || timestampsClose(event.getCreatedAt(), timestamp);
    }

    private boolean timestampsClose(Timestamp a, Timestamp b) {
        if (a == null || b == null) {
            return false;
        }
        return Math.abs(a.getTime() - b.getTime()) < 10000;
    }

    private void touchSession(int sessionId) {
        String sql = "UPDATE GHChatHistory SET last_update = CURRENT_TIMESTAMP WHERE id = ?";
        try (PreparedStatement stmt = connection.prepareStatement(sql)) {
            stmt.setInt(1, sessionId);
            stmt.executeUpdate();
        } catch (SQLException e) {
            Msg.warn(this, "Failed to touch session for transcript event: " + e.getMessage());
        }
    }

    private void deleteEvent(long eventId) {
        if (eventId <= 0) {
            return;
        }
        String sql = "DELETE FROM GHChatTranscriptEvents WHERE id = ?";
        try (PreparedStatement stmt = connection.prepareStatement(sql)) {
            stmt.setLong(1, eventId);
            stmt.executeUpdate();
        } catch (SQLException e) {
            Msg.warn(this, "Failed to delete duplicate transcript event " + eventId + ": " + e.getMessage());
        }
    }

    private String buildToolMetadata(int sessionId, Tool tool, JsonObject args) {
        JsonObject metadata = new JsonObject();
        metadata.addProperty("tool", tool.getName());
        metadata.addProperty("source", tool.getSource());
        if (args != null) {
            metadata.add("args", args.deepCopy());
        }
        return mergeActiveReActMetadata(sessionId, metadata.toString());
    }

    private String buildApprovalRequestedMetadata(int sessionId, String requestId, String toolName, String toolSource,
                                                  String riskTier, JsonObject args) {
        JsonObject metadata = new JsonObject();
        metadata.addProperty("request_id", requestId);
        metadata.addProperty("tool", toolName);
        metadata.addProperty("source", toolSource);
        metadata.addProperty("risk_tier", riskTier);
        metadata.addProperty("pending", true);
        if (args != null) {
            metadata.add("args", args.deepCopy());
        }
        return mergeActiveReActMetadata(sessionId, metadata.toString());
    }

    private String buildApprovalDecisionMetadata(int sessionId, String requestId, String toolName, String toolSource,
                                                 String riskTier, String decision, String scope) {
        JsonObject metadata = new JsonObject();
        metadata.addProperty("request_id", requestId);
        metadata.addProperty("tool", toolName);
        metadata.addProperty("source", toolSource);
        if (riskTier != null) {
            metadata.addProperty("risk_tier", riskTier);
        }
        if (decision != null) {
            metadata.addProperty("decision", decision);
        }
        if (scope != null) {
            metadata.addProperty("scope", scope);
        }
        return mergeActiveReActMetadata(sessionId, metadata.toString());
    }

    private String buildTodoMetadata(String summary, List<TodoListManager.Todo> todos, Integer iteration,
                                     String reactRunId, String objective) {
        JsonObject metadata = new JsonObject();
        if (summary != null) {
            metadata.addProperty("summary", summary);
        }
        if (iteration != null) {
            metadata.addProperty("iteration", iteration);
        }
        JsonArray todoArray = new JsonArray();
        int pending = 0;
        int inProgress = 0;
        int complete = 0;
        if (todos != null) {
            for (TodoListManager.Todo todo : todos) {
                if (todo == null) {
                    continue;
                }
                JsonObject item = new JsonObject();
                item.addProperty("task", todo.getTask());
                item.addProperty("status", todo.getStatus().name());
                if (todo.getEvidence() != null) {
                    item.addProperty("evidence", todo.getEvidence());
                }
                item.addProperty("priority", todo.getPriority());
                todoArray.add(item);
                switch (todo.getStatus()) {
                    case PENDING -> pending++;
                    case IN_PROGRESS -> inProgress++;
                    case COMPLETE -> complete++;
                }
            }
        }
        metadata.add("todos", todoArray);
        metadata.addProperty("pending_count", pending);
        metadata.addProperty("in_progress_count", inProgress);
        metadata.addProperty("complete_count", complete);
        metadata.addProperty("total_count", pending + inProgress + complete);
        addReActMetadata(metadata, reactRunId, objective, null, false);
        return metadata.toString();
    }

    private String buildFindingMetadata(Integer iteration, String reactRunId) {
        JsonObject metadata = new JsonObject();
        if (iteration != null) {
            metadata.addProperty("iteration", iteration);
        }
        addReActMetadata(metadata, reactRunId, null, null, false);
        return metadata.toString();
    }

    private String buildIterationNoticeMetadata(Integer iteration, String category,
                                               String reactRunId, String objective) {
        JsonObject metadata = new JsonObject();
        if (iteration != null) {
            metadata.addProperty("iteration", iteration);
        }
        if (category != null && !category.isBlank()) {
            metadata.addProperty("category", category);
        }
        addReActMetadata(metadata, reactRunId, objective, null, false);
        return metadata.toString();
    }

    private String buildReActAssistantMetadata(String reactRunId, String objective, String status) {
        JsonObject metadata = new JsonObject();
        addReActMetadata(metadata, reactRunId, objective, status, true);
        return metadata.toString();
    }

    private void addReActMetadata(JsonObject metadata, String reactRunId, String objective,
                                  String status, boolean reactFinal) {
        if (metadata == null || reactRunId == null || reactRunId.isBlank()) {
            return;
        }
        metadata.addProperty("react_run_id", reactRunId);
        if (objective != null && !objective.isBlank()) {
            metadata.addProperty("react_objective", objective);
        }
        if (status != null && !status.isBlank()) {
            metadata.addProperty("react_status", status);
        }
        if (reactFinal) {
            metadata.addProperty("react_final", true);
        }
    }

    private String mergeActiveReActMetadata(int sessionId, String metadataJson) {
        ActiveReActRun active = activeReActRuns.get(sessionId);
        if (active == null) {
            return metadataJson;
        }
        JsonObject metadata = parseMetadata(metadataJson);
        if (metadata == null) {
            metadata = new JsonObject();
        }
        addReActMetadata(metadata, active.reactRunId, active.objective, null, false);
        return metadata.toString();
    }

    private JsonObject parseMetadata(String metadataJson) {
        if (metadataJson == null || metadataJson.isBlank()) {
            return null;
        }
        try {
            JsonElement element = JsonParser.parseString(metadataJson);
            if (element.isJsonObject()) {
                return element.getAsJsonObject();
            }
        } catch (Exception e) {
            Msg.warn(this, "Failed to parse transcript metadata: " + e.getMessage());
        }
        return null;
    }

    private String getMetadataString(JsonObject metadata, String key) {
        if (metadata == null || !metadata.has(key) || metadata.get(key).isJsonNull()) {
            return null;
        }
        try {
            return metadata.get(key).getAsString();
        } catch (Exception ignored) {
            return null;
        }
    }

    private int getMetadataInt(JsonObject metadata, String key) {
        if (metadata == null || !metadata.has(key) || metadata.get(key).isJsonNull()) {
            return 0;
        }
        try {
            return metadata.get(key).getAsInt();
        } catch (Exception ignored) {
            return 0;
        }
    }

    private String extractActiveTodo(JsonObject todoMetadata) {
        if (todoMetadata == null || !todoMetadata.has("todos")) {
            return null;
        }
        JsonArray todos = todoMetadata.getAsJsonArray("todos");
        String pendingTodo = null;
        for (JsonElement element : todos) {
            if (!element.isJsonObject()) {
                continue;
            }
            JsonObject todo = element.getAsJsonObject();
            String status = getMetadataString(todo, "status");
            String task = getMetadataString(todo, "task");
            if (task == null || task.isBlank()) {
                continue;
            }
            if ("IN_PROGRESS".equalsIgnoreCase(status)) {
                return task;
            }
            if (pendingTodo == null && "PENDING".equalsIgnoreCase(status)) {
                pendingTodo = task;
            }
        }
        return pendingTodo;
    }

    private String normalizeBridgeText(String value, int maxChars) {
        if (value == null) {
            return "";
        }
        String normalized = value.replace("\r\n", "\n").replace('\r', '\n').trim();
        if (normalized.length() > maxChars) {
            normalized = normalized.substring(0, Math.max(0, maxChars - 3)).trim() + "...";
        }
        return normalized;
    }
}
