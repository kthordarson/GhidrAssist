package ghidrassist.db.migration;

import java.sql.Connection;
import java.sql.SQLException;
import java.sql.Statement;

/**
 * Migration V7: LLM Renames tracking table.
 * Records which symbols were renamed by LLM suggestions so that
 * symbol push can assign correct provenance ("llm" vs "user").
 */
public class V7_LlmRenames implements SchemaMigration {

    @Override
    public int getVersion() {
        return 7;
    }

    @Override
    public String getDescription() {
        return "Add llm_renames table for tracking LLM-suggested symbol renames";
    }

    @Override
    public void migrate(Connection connection) throws SQLException {
        try (Statement stmt = connection.createStatement()) {
            stmt.execute(
                "CREATE TABLE IF NOT EXISTS llm_renames (" +
                "    binary_id TEXT NOT NULL," +
                "    address INTEGER NOT NULL," +
                "    symbol_type TEXT NOT NULL DEFAULT 'function'," +
                "    new_name TEXT NOT NULL," +
                "    created_at INTEGER NOT NULL," +
                "    PRIMARY KEY (binary_id, address, symbol_type)" +
                ")"
            );
        }
    }
}
