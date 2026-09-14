package ghidrassist.db.migration;

import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

/**
 * Migration V12: link transcript events to persisted message rows/order for deterministic reload.
 */
public class V12_TranscriptMessageLinkage implements SchemaMigration {

    @Override
    public int getVersion() {
        return 12;
    }

    @Override
    public String getDescription() {
        return "Add transcript source message linkage columns";
    }

    @Override
    public void migrate(Connection connection) throws SQLException {
        try (Statement stmt = connection.createStatement()) {
            if (!columnExists(connection, "GHChatTranscriptEvents", "source_message_id")) {
                stmt.execute("ALTER TABLE GHChatTranscriptEvents ADD COLUMN source_message_id INTEGER");
            }
            if (!columnExists(connection, "GHChatTranscriptEvents", "source_message_order")) {
                stmt.execute("ALTER TABLE GHChatTranscriptEvents ADD COLUMN source_message_order INTEGER");
            }
            stmt.execute("""
                CREATE INDEX IF NOT EXISTS idx_chat_transcript_message_link
                ON GHChatTranscriptEvents(session_id, source_message_order, source_message_id)
            """);
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
}
