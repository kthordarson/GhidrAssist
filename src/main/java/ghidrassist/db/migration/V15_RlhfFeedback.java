package ghidrassist.db.migration;

import ghidra.framework.preferences.Preferences;
import ghidra.util.Msg;

import java.io.File;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Savepoint;
import java.sql.Statement;

/**
 * Migration V15: RLHF feedback table.
 * Feedback previously lived in a separate ghidrassist_rlhf.db file. This creates the
 * table in the analysis database and imports rows from the legacy file if it exists.
 * The legacy file is left untouched.
 */
public class V15_RlhfFeedback implements SchemaMigration {

    private static final String LEGACY_PATH_PROPERTY = "GhidrAssist.RLHFDatabasePath";
    private static final String LEGACY_DEFAULT_PATH = "ghidrassist_rlhf.db";

    @Override
    public int getVersion() {
        return 15;
    }

    @Override
    public String getDescription() {
        return "Add feedback table (merged from legacy RLHF database)";
    }

    @Override
    public void migrate(Connection connection) throws SQLException {
        try (Statement stmt = connection.createStatement()) {
            stmt.execute(
                "CREATE TABLE IF NOT EXISTS feedback (" +
                "    id INTEGER PRIMARY KEY AUTOINCREMENT," +
                "    model_name TEXT NOT NULL," +
                "    prompt_context TEXT NOT NULL," +
                "    system_context TEXT NOT NULL," +
                "    response TEXT NOT NULL," +
                "    feedback INTEGER NOT NULL" + // 1 for thumbs up, 0 for thumbs down
                ")"
            );
        }

        // Import failures must not fail the migration (recovery would drop Graph-RAG tables)
        Savepoint savepoint = connection.setSavepoint("rlhf_import");
        try {
            importLegacyFeedback(connection);
            connection.releaseSavepoint(savepoint);
        } catch (Exception e) {
            connection.rollback(savepoint);
            Msg.warn(this, "Could not import legacy RLHF feedback: " + e.getMessage());
        }
    }

    private void importLegacyFeedback(Connection connection) throws Exception {
        String legacyPath = Preferences.getProperty(LEGACY_PATH_PROPERTY, LEGACY_DEFAULT_PATH);
        if (legacyPath == null || legacyPath.isBlank()) {
            return;
        }
        File legacyFile = new File(legacyPath.trim()).getCanonicalFile();
        if (!legacyFile.isFile()) {
            return;
        }
        String currentPath = getMainDatabasePath(connection);
        if (currentPath != null && new File(currentPath).getCanonicalFile().equals(legacyFile)) {
            return;
        }

        int imported = 0;
        String insertSql = "INSERT INTO feedback (model_name, prompt_context, system_context, response, feedback) "
                + "VALUES (?, ?, ?, ?, ?)";
        try (Connection legacy = DriverManager.getConnection("jdbc:sqlite:" + legacyFile.getPath());
             Statement check = legacy.createStatement();
             ResultSet tables = check.executeQuery(
                 "SELECT name FROM sqlite_master WHERE type='table' AND name='feedback'")) {
            if (!tables.next()) {
                return;
            }
            try (Statement select = legacy.createStatement();
                 ResultSet rs = select.executeQuery(
                     "SELECT model_name, prompt_context, system_context, response, feedback FROM feedback ORDER BY id");
                 PreparedStatement insert = connection.prepareStatement(insertSql)) {
                while (rs.next()) {
                    insert.setString(1, rs.getString(1));
                    insert.setString(2, rs.getString(2));
                    insert.setString(3, rs.getString(3));
                    insert.setString(4, rs.getString(4));
                    insert.setInt(5, rs.getInt(5));
                    insert.executeUpdate();
                    imported++;
                }
            }
        }
        Msg.info(this, "Imported " + imported + " RLHF feedback rows from " + legacyFile.getPath());
    }

    private String getMainDatabasePath(Connection connection) throws SQLException {
        try (Statement stmt = connection.createStatement();
             ResultSet rs = stmt.executeQuery("PRAGMA database_list")) {
            while (rs.next()) {
                if ("main".equals(rs.getString("name"))) {
                    return rs.getString("file");
                }
            }
        }
        return null;
    }
}
