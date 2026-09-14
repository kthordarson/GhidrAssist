package ghidrassist.db.migration;

import java.sql.Connection;
import java.sql.SQLException;
import java.sql.Statement;

/**
 * Migration V10: add first-class graph node category storage.
 */
public class V10_GraphNodeCategory implements SchemaMigration {

    @Override
    public int getVersion() {
        return 10;
    }

    @Override
    public String getDescription() {
        return "Add category column to graph nodes";
    }

    @Override
    public void migrate(Connection connection) throws SQLException {
        try (Statement stmt = connection.createStatement()) {
            stmt.execute("ALTER TABLE graph_nodes ADD COLUMN category TEXT");
        } catch (SQLException ignored) {
            // Column may already exist.
        }
    }
}
