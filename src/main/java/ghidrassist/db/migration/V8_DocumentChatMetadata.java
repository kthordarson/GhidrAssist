package ghidrassist.db.migration;

import java.sql.Connection;
import java.sql.SQLException;
import java.sql.Statement;

/**
 * Migration V8: document chat metadata for SymGraph-backed query chats.
 */
public class V8_DocumentChatMetadata implements SchemaMigration {

    @Override
    public int getVersion() {
        return 8;
    }

    @Override
    public String getDescription() {
        return "Add document chat metadata table for SymGraph document sync";
    }

    @Override
    public void migrate(Connection connection) throws SQLException {
        try (Statement stmt = connection.createStatement()) {
            stmt.execute(
                "CREATE TABLE IF NOT EXISTS GHDocumentChatMetadata (" +
                "    session_id INTEGER PRIMARY KEY," +
                "    is_document_chat INTEGER NOT NULL DEFAULT 0," +
                "    symgraph_document_identity_id TEXT," +
                "    symgraph_document_version INTEGER," +
                "    symgraph_doc_type TEXT," +
                "    symgraph_last_synced_at INTEGER," +
                "    symgraph_source_sha256 TEXT," +
                "    FOREIGN KEY(session_id) REFERENCES GHChatHistory(id) ON DELETE CASCADE" +
                ")"
            );
        }
    }
}
