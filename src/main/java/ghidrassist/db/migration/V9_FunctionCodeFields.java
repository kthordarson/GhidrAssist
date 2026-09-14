package ghidrassist.db.migration;

import java.sql.Connection;
import java.sql.SQLException;
import java.sql.Statement;

/**
 * Migration V9: add first-class function signature and dual code fields.
 */
public class V9_FunctionCodeFields implements SchemaMigration {

    @Override
    public int getVersion() {
        return 9;
    }

    @Override
    public String getDescription() {
        return "Add signature, decompiled_code, and disassembly to graph nodes";
    }

    @Override
    public void migrate(Connection connection) throws SQLException {
        try (Statement stmt = connection.createStatement()) {
            stmt.execute("ALTER TABLE graph_nodes ADD COLUMN signature TEXT");
        } catch (SQLException ignored) {
            // Column may already exist.
        }

        try (Statement stmt = connection.createStatement()) {
            stmt.execute("ALTER TABLE graph_nodes ADD COLUMN decompiled_code TEXT");
        } catch (SQLException ignored) {
            // Column may already exist.
        }

        try (Statement stmt = connection.createStatement()) {
            stmt.execute("ALTER TABLE graph_nodes ADD COLUMN disassembly TEXT");
        } catch (SQLException ignored) {
            // Column may already exist.
        }

        try (Statement stmt = connection.createStatement()) {
            stmt.execute("UPDATE graph_nodes SET decompiled_code = raw_content "
                    + "WHERE decompiled_code IS NULL AND raw_content IS NOT NULL");
            stmt.execute("UPDATE graph_nodes SET raw_content = decompiled_code "
                    + "WHERE raw_content IS NULL AND decompiled_code IS NOT NULL");

            stmt.execute("DROP TRIGGER IF EXISTS graph_nodes_ai");
            stmt.execute("DROP TRIGGER IF EXISTS graph_nodes_ad");
            stmt.execute("DROP TRIGGER IF EXISTS graph_nodes_au");
            stmt.execute("DROP TABLE IF EXISTS node_fts");

            stmt.execute("CREATE VIRTUAL TABLE node_fts USING fts5("
                    + "id, "
                    + "name, "
                    + "signature, "
                    + "llm_summary, "
                    + "security_flags, "
                    + "content='graph_nodes', "
                    + "content_rowid='rowid'"
                    + ")");

            stmt.execute("CREATE TRIGGER IF NOT EXISTS graph_nodes_ai AFTER INSERT ON graph_nodes BEGIN "
                    + "INSERT INTO node_fts(rowid, id, name, signature, llm_summary, security_flags) "
                    + "VALUES (NEW.rowid, NEW.id, NEW.name, NEW.signature, NEW.llm_summary, NEW.security_flags); "
                    + "END");

            stmt.execute("CREATE TRIGGER IF NOT EXISTS graph_nodes_ad AFTER DELETE ON graph_nodes BEGIN "
                    + "INSERT INTO node_fts(node_fts, rowid, id, name, signature, llm_summary, security_flags) "
                    + "VALUES ('delete', OLD.rowid, OLD.id, OLD.name, OLD.signature, OLD.llm_summary, OLD.security_flags); "
                    + "END");

            stmt.execute("CREATE TRIGGER IF NOT EXISTS graph_nodes_au AFTER UPDATE ON graph_nodes BEGIN "
                    + "INSERT INTO node_fts(node_fts, rowid, id, name, signature, llm_summary, security_flags) "
                    + "VALUES ('delete', OLD.rowid, OLD.id, OLD.name, OLD.signature, OLD.llm_summary, OLD.security_flags); "
                    + "INSERT INTO node_fts(rowid, id, name, signature, llm_summary, security_flags) "
                    + "VALUES (NEW.rowid, NEW.id, NEW.name, NEW.signature, NEW.llm_summary, NEW.security_flags); "
                    + "END");

            stmt.execute("INSERT INTO node_fts(rowid, id, name, signature, llm_summary, security_flags) "
                    + "SELECT rowid, id, name, signature, llm_summary, security_flags FROM graph_nodes");
        }
    }
}
