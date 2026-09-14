package ghidrassist.db.migration;

import java.sql.Connection;
import java.sql.SQLException;
import java.sql.Statement;

/**
 * Migration V11: add unified transcript, artifact, and approval persistence.
 */
public class V11_TranscriptAndApprovalSchema implements SchemaMigration {

    @Override
    public int getVersion() {
        return 11;
    }

    @Override
    public String getDescription() {
        return "Add transcript, artifact, and approval grant tables";
    }

    @Override
    public void migrate(Connection connection) throws SQLException {
        try (Statement stmt = connection.createStatement()) {
            stmt.execute("""
                CREATE TABLE IF NOT EXISTS GHChatTranscriptEvents (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id INTEGER NOT NULL,
                    program_hash TEXT,
                    correlation_id TEXT,
                    parent_event_id INTEGER,
                    event_kind TEXT NOT NULL,
                    role TEXT,
                    title TEXT,
                    content_text TEXT,
                    preview_text TEXT,
                    metadata_json TEXT,
                    artifact_id TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY(session_id) REFERENCES GHChatHistory(id) ON DELETE CASCADE
                )
            """);

            stmt.execute("""
                CREATE INDEX IF NOT EXISTS idx_chat_transcript_session
                ON GHChatTranscriptEvents(session_id, id)
            """);

            stmt.execute("""
                CREATE TABLE IF NOT EXISTS GHChatArtifacts (
                    artifact_id TEXT PRIMARY KEY,
                    session_id INTEGER NOT NULL,
                    event_id INTEGER,
                    artifact_type TEXT,
                    storage_path TEXT NOT NULL,
                    preview_text TEXT,
                    byte_size INTEGER,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY(session_id) REFERENCES GHChatHistory(id) ON DELETE CASCADE,
                    FOREIGN KEY(event_id) REFERENCES GHChatTranscriptEvents(id) ON DELETE SET NULL
                )
            """);

            stmt.execute("""
                CREATE TABLE IF NOT EXISTS GHChatApprovalGrants (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id INTEGER NOT NULL,
                    tool_name TEXT NOT NULL,
                    risk_tier TEXT,
                    scope TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE(session_id, tool_name),
                    FOREIGN KEY(session_id) REFERENCES GHChatHistory(id) ON DELETE CASCADE
                )
            """);
        }
    }
}
