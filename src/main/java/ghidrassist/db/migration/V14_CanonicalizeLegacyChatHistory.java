package ghidrassist.db.migration;

import ghidra.util.Msg;
import ghidrassist.chat.util.RoleNormalizer;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Migration V14: move mixed legacy chat history into GHChatMessages.
 */
public class V14_CanonicalizeLegacyChatHistory implements SchemaMigration {
    private static final int TEMP_ORDER_OFFSET = 1_000_000;
    private static final Pattern LEGACY_MESSAGE_PATTERN = Pattern.compile(
        "\\*\\*(User|Assistant|GhidrAssist|Error|Tool Call|Tool Response)\\*\\*:\\s*\\n"
            + "(.*?)(?=\\*\\*(User|Assistant|GhidrAssist|Error|Tool Call|Tool Response)\\*\\*:\\s*\\n|$)",
        Pattern.DOTALL
    );

    @Override
    public int getVersion() {
        return 14;
    }

    @Override
    public String getDescription() {
        return "Canonicalize legacy chat history blobs into per-message storage";
    }

    @Override
    public void migrate(Connection connection) throws SQLException {
        boolean hasSessionId = columnExists(connection, "GHChatMessages", "session_id");
        boolean hasSequenceNumber = columnExists(connection, "GHChatMessages", "sequence_number");

        List<SessionBlob> sessions = loadSessionsWithLegacyBlobs(connection);
        int migratedSessions = 0;
        int insertedMessages = 0;

        for (SessionBlob session : sessions) {
            List<LegacyMessage> legacyMessages = parseLegacyMessages(session.conversation);
            if (legacyMessages.isEmpty()) {
                clearLegacyBlob(connection, session.id);
                continue;
            }

            List<DbMessage> existingMessages = loadExistingMessages(connection, session.programHash, session.id);
            List<DbMessage> canonicalMessages = buildCanonicalMessages(legacyMessages, existingMessages);

            moveExistingMessagesToTemporaryOrders(connection, session.programHash, session.id, hasSequenceNumber);
            for (int i = 0; i < canonicalMessages.size(); i++) {
                DbMessage message = canonicalMessages.get(i);
                if (message.id != null) {
                    updateExistingMessageOrder(connection, message, i, hasSequenceNumber);
                    updateTranscriptMessageOrder(connection, session.id, message, i);
                } else {
                    insertMigratedMessage(connection, session.programHash, session.id, message, i,
                        hasSessionId, hasSequenceNumber);
                    insertedMessages++;
                }
            }
            clearLegacyBlob(connection, session.id);
            migratedSessions++;
        }

        Msg.info(this, "Canonicalized legacy chat history for " + migratedSessions
            + " session(s), inserted " + insertedMessages + " message(s)");
    }

    private List<SessionBlob> loadSessionsWithLegacyBlobs(Connection connection) throws SQLException {
        String sql = """
            SELECT id, program_hash, conversation
            FROM GHChatHistory
            WHERE conversation IS NOT NULL
              AND TRIM(conversation) != ''
            ORDER BY id ASC
        """;
        List<SessionBlob> sessions = new ArrayList<>();
        try (PreparedStatement stmt = connection.prepareStatement(sql);
             ResultSet rs = stmt.executeQuery()) {
            while (rs.next()) {
                sessions.add(new SessionBlob(
                    rs.getInt("id"),
                    rs.getString("program_hash"),
                    rs.getString("conversation")
                ));
            }
        }
        return sessions;
    }

    private List<LegacyMessage> parseLegacyMessages(String conversation) {
        List<LegacyMessage> messages = new ArrayList<>();
        Matcher matcher = LEGACY_MESSAGE_PATTERN.matcher(conversation);
        while (matcher.find()) {
            String role = RoleNormalizer.normalize(matcher.group(1));
            String content = matcher.group(2) != null ? matcher.group(2).trim() : "";
            if (!content.isEmpty()) {
                messages.add(new LegacyMessage(role, content));
            }
        }
        return messages;
    }

    private List<DbMessage> loadExistingMessages(Connection connection, String programHash, int sessionId)
            throws SQLException {
        String sql = """
            SELECT id, role, content_text, message_order, created_at,
                   provider_type, native_message_data, message_type
            FROM GHChatMessages
            WHERE program_hash = ? AND chat_id = ?
            ORDER BY message_order ASC, id ASC
        """;
        List<DbMessage> messages = new ArrayList<>();
        try (PreparedStatement stmt = connection.prepareStatement(sql)) {
            stmt.setString(1, programHash);
            stmt.setInt(2, sessionId);
            try (ResultSet rs = stmt.executeQuery()) {
                while (rs.next()) {
                    messages.add(new DbMessage(
                        rs.getInt("id"),
                        RoleNormalizer.normalize(rs.getString("role")),
                        rs.getString("content_text"),
                        rs.getInt("message_order"),
                        rs.getTimestamp("created_at"),
                        rs.getString("provider_type"),
                        rs.getString("native_message_data"),
                        rs.getString("message_type")
                    ));
                }
            }
        }
        return messages;
    }

    private List<DbMessage> buildCanonicalMessages(List<LegacyMessage> legacyMessages,
                                                   List<DbMessage> existingMessages) {
        List<DbMessage> canonical = new ArrayList<>();
        Set<Integer> usedExistingIds = new HashSet<>();

        for (LegacyMessage legacyMessage : legacyMessages) {
            DbMessage match = findFirstUnusedMatch(legacyMessage, existingMessages, usedExistingIds);
            if (match != null) {
                usedExistingIds.add(match.id);
                match.role = legacyMessage.role;
                match.content = legacyMessage.content;
                canonical.add(match);
            } else {
                canonical.add(DbMessage.newMigrated(legacyMessage.role, legacyMessage.content));
            }
        }

        for (DbMessage existingMessage : existingMessages) {
            if (existingMessage.id != null && !usedExistingIds.contains(existingMessage.id)) {
                canonical.add(existingMessage);
            }
        }

        return canonical;
    }

    private DbMessage findFirstUnusedMatch(LegacyMessage legacyMessage, List<DbMessage> existingMessages,
                                           Set<Integer> usedExistingIds) {
        String legacyContent = normalizeContentForMatch(legacyMessage.content);
        for (DbMessage existingMessage : existingMessages) {
            if (existingMessage.id == null || usedExistingIds.contains(existingMessage.id)) {
                continue;
            }
            if (!legacyMessage.role.equals(RoleNormalizer.normalize(existingMessage.role))) {
                continue;
            }
            if (legacyContent.equals(normalizeContentForMatch(existingMessage.content))) {
                return existingMessage;
            }
        }
        return null;
    }

    private String normalizeContentForMatch(String content) {
        return content == null ? "" : content.replace("\r\n", "\n").replace('\r', '\n').trim();
    }

    private void moveExistingMessagesToTemporaryOrders(Connection connection, String programHash, int sessionId,
                                                       boolean hasSequenceNumber) throws SQLException {
        String sql = hasSequenceNumber
            ? "UPDATE GHChatMessages SET message_order = -(message_order + ?), "
                + "sequence_number = -(sequence_number + ?) WHERE program_hash = ? AND chat_id = ?"
            : "UPDATE GHChatMessages SET message_order = -(message_order + ?) "
                + "WHERE program_hash = ? AND chat_id = ?";
        try (PreparedStatement stmt = connection.prepareStatement(sql)) {
            stmt.setInt(1, TEMP_ORDER_OFFSET);
            if (hasSequenceNumber) {
                stmt.setInt(2, TEMP_ORDER_OFFSET);
                stmt.setString(3, programHash);
                stmt.setInt(4, sessionId);
            } else {
                stmt.setString(2, programHash);
                stmt.setInt(3, sessionId);
            }
            stmt.executeUpdate();
        }
    }

    private void updateExistingMessageOrder(Connection connection, DbMessage message, int order,
                                            boolean hasSequenceNumber) throws SQLException {
        String sql = hasSequenceNumber
            ? "UPDATE GHChatMessages SET message_order = ?, sequence_number = ?, role = ?, content_text = ? WHERE id = ?"
            : "UPDATE GHChatMessages SET message_order = ?, role = ?, content_text = ? WHERE id = ?";
        try (PreparedStatement stmt = connection.prepareStatement(sql)) {
            stmt.setInt(1, order);
            if (hasSequenceNumber) {
                stmt.setInt(2, order);
                stmt.setString(3, message.role);
                stmt.setString(4, message.content);
                stmt.setInt(5, message.id);
            } else {
                stmt.setString(2, message.role);
                stmt.setString(3, message.content);
                stmt.setInt(4, message.id);
            }
            stmt.executeUpdate();
        }
    }

    private void insertMigratedMessage(Connection connection, String programHash, int sessionId,
                                       DbMessage message, int order, boolean hasSessionId,
                                       boolean hasSequenceNumber) throws SQLException {
        List<String> columns = new ArrayList<>();
        List<String> values = new ArrayList<>();
        columns.add("program_hash");
        values.add("?");
        columns.add("chat_id");
        values.add("?");
        if (hasSessionId) {
            columns.add("session_id");
            values.add("?");
        }
        if (hasSequenceNumber) {
            columns.add("sequence_number");
            values.add("?");
        }
        columns.add("message_order");
        values.add("?");
        columns.add("provider_type");
        values.add("?");
        columns.add("native_message_data");
        values.add("?");
        columns.add("role");
        values.add("?");
        columns.add("content_text");
        values.add("?");
        columns.add("message_type");
        values.add("?");
        columns.add("created_at");
        values.add("CURRENT_TIMESTAMP");
        columns.add("updated_at");
        values.add("CURRENT_TIMESTAMP");

        String sql = "INSERT INTO GHChatMessages (" + String.join(", ", columns)
            + ") VALUES (" + String.join(", ", values) + ")";
        try (PreparedStatement stmt = connection.prepareStatement(sql)) {
            int index = 1;
            stmt.setString(index++, programHash);
            stmt.setInt(index++, sessionId);
            if (hasSessionId) {
                stmt.setInt(index++, sessionId);
            }
            if (hasSequenceNumber) {
                stmt.setInt(index++, order);
            }
            stmt.setInt(index++, order);
            stmt.setString(index++, message.providerType);
            stmt.setString(index++, message.nativeMessageData);
            stmt.setString(index++, message.role);
            stmt.setString(index++, message.content);
            stmt.setString(index, message.messageType);
            stmt.executeUpdate();
        }
    }

    private void updateTranscriptMessageOrder(Connection connection, int sessionId, DbMessage message, int order)
            throws SQLException {
        if (!columnExists(connection, "GHChatTranscriptEvents", "source_message_order")) {
            return;
        }
        String sql = """
            UPDATE GHChatTranscriptEvents
            SET source_message_order = ?
            WHERE session_id = ?
              AND (
                    source_message_id = ?
                    OR (
                        source_message_id IS NULL
                        AND source_message_order = ?
                        AND TRIM(COALESCE(content_text, '')) = TRIM(COALESCE(?, ''))
                    )
              )
        """;
        try (PreparedStatement stmt = connection.prepareStatement(sql)) {
            stmt.setInt(1, order);
            stmt.setInt(2, sessionId);
            stmt.setInt(3, message.id);
            stmt.setInt(4, message.order);
            stmt.setString(5, message.content);
            stmt.executeUpdate();
        }
    }

    private void clearLegacyBlob(Connection connection, int sessionId) throws SQLException {
        try (PreparedStatement stmt = connection.prepareStatement(
                "UPDATE GHChatHistory SET conversation = '' WHERE id = ?")) {
            stmt.setInt(1, sessionId);
            stmt.executeUpdate();
        }
    }

    private boolean columnExists(Connection connection, String tableName, String columnName) throws SQLException {
        try (Statement stmt = connection.createStatement();
             ResultSet rs = stmt.executeQuery("PRAGMA table_info(" + tableName + ")")) {
            while (rs.next()) {
                if (columnName.equalsIgnoreCase(rs.getString("name"))) {
                    return true;
                }
            }
        }
        return false;
    }

    private record SessionBlob(int id, String programHash, String conversation) {
    }

    private record LegacyMessage(String role, String content) {
    }

    private static class DbMessage {
        private final Integer id;
        private String role;
        private String content;
        @SuppressWarnings("unused")
        private final int order;
        @SuppressWarnings("unused")
        private final Timestamp createdAt;
        private final String providerType;
        private final String nativeMessageData;
        private final String messageType;

        private DbMessage(Integer id, String role, String content, int order, Timestamp createdAt,
                          String providerType, String nativeMessageData, String messageType) {
            this.id = id;
            this.role = role;
            this.content = content;
            this.order = order;
            this.createdAt = createdAt;
            this.providerType = providerType != null ? providerType : "unknown";
            this.nativeMessageData = nativeMessageData != null ? nativeMessageData : "{}";
            this.messageType = messageType != null ? messageType : "standard";
        }

        private static DbMessage newMigrated(String role, String content) {
            return new DbMessage(null, role, content, -1, null, "migrated", "{}", "standard");
        }
    }
}
