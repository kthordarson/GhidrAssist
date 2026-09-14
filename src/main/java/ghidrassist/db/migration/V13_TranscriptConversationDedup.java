package ghidrassist.db.migration;

import ghidra.util.Msg;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;

/**
 * Repairs duplicate conversational transcript rows created during the
 * transition from heuristic backfill to explicitly linked transcript events.
 *
 * Pattern repaired:
 * - earlier user/assistant transcript row with matching content but no source linkage
 * - later duplicate user/assistant transcript row with source_message_id/order populated
 *
 * The earlier row is upgraded to the linked canonical row and the later duplicate is removed.
 */
public class V13_TranscriptConversationDedup implements SchemaMigration {

    @Override
    public int getVersion() {
        return 13;
    }

    @Override
    public String getDescription() {
        return "Deduplicate linked conversational transcript rows";
    }

    @Override
    public void migrate(Connection connection) throws SQLException {
        String candidateSql = """
            SELECT later.id, later.session_id, later.event_kind, later.content_text,
                   later.source_message_id, later.source_message_order
            FROM GHChatTranscriptEvents later
            WHERE later.event_kind IN ('user_message', 'assistant_message')
              AND (later.source_message_id IS NOT NULL OR later.source_message_order IS NOT NULL)
              AND EXISTS (
                    SELECT 1
                    FROM GHChatTranscriptEvents earlier
                    WHERE earlier.session_id = later.session_id
                      AND earlier.event_kind = later.event_kind
                      AND earlier.id < later.id
                      AND earlier.source_message_id IS NULL
                      AND earlier.source_message_order IS NULL
                      AND TRIM(COALESCE(earlier.content_text, '')) = TRIM(COALESCE(later.content_text, ''))
              )
            ORDER BY later.session_id ASC, later.id ASC
        """;

        String findEarlierSql = """
            SELECT id
            FROM GHChatTranscriptEvents
            WHERE session_id = ?
              AND event_kind = ?
              AND id < ?
              AND source_message_id IS NULL
              AND source_message_order IS NULL
              AND TRIM(COALESCE(content_text, '')) = TRIM(COALESCE(?, ''))
            ORDER BY id ASC
            LIMIT 1
        """;

        String updateEarlierSql = """
            UPDATE GHChatTranscriptEvents
            SET source_message_id = COALESCE(source_message_id, ?),
                source_message_order = COALESCE(source_message_order, ?)
            WHERE id = ?
        """;

        String deleteLaterSql = "DELETE FROM GHChatTranscriptEvents WHERE id = ?";

        int repaired = 0;
        try (PreparedStatement candidateStmt = connection.prepareStatement(candidateSql);
             PreparedStatement findEarlierStmt = connection.prepareStatement(findEarlierSql);
             PreparedStatement updateEarlierStmt = connection.prepareStatement(updateEarlierSql);
             PreparedStatement deleteLaterStmt = connection.prepareStatement(deleteLaterSql);
             ResultSet rs = candidateStmt.executeQuery()) {

            while (rs.next()) {
                long laterId = rs.getLong("id");
                int sessionId = rs.getInt("session_id");
                String eventKind = rs.getString("event_kind");
                String contentText = rs.getString("content_text");
                Integer sourceMessageId = getNullableInt(rs, "source_message_id");
                Integer sourceMessageOrder = getNullableInt(rs, "source_message_order");

                findEarlierStmt.setInt(1, sessionId);
                findEarlierStmt.setString(2, eventKind);
                findEarlierStmt.setLong(3, laterId);
                findEarlierStmt.setString(4, contentText);

                try (ResultSet earlierRs = findEarlierStmt.executeQuery()) {
                    if (!earlierRs.next()) {
                        continue;
                    }

                    long earlierId = earlierRs.getLong("id");

                    if (sourceMessageId != null) {
                        updateEarlierStmt.setInt(1, sourceMessageId);
                    } else {
                        updateEarlierStmt.setNull(1, java.sql.Types.INTEGER);
                    }
                    if (sourceMessageOrder != null) {
                        updateEarlierStmt.setInt(2, sourceMessageOrder);
                    } else {
                        updateEarlierStmt.setNull(2, java.sql.Types.INTEGER);
                    }
                    updateEarlierStmt.setLong(3, earlierId);
                    updateEarlierStmt.executeUpdate();

                    deleteLaterStmt.setLong(1, laterId);
                    deleteLaterStmt.executeUpdate();
                    repaired++;
                }
            }
        }

        Msg.info(this, "Transcript conversational dedup repair updated " + repaired + " duplicate rows");
    }

    private Integer getNullableInt(ResultSet rs, String columnName) throws SQLException {
        int value = rs.getInt(columnName);
        return rs.wasNull() ? null : value;
    }
}
