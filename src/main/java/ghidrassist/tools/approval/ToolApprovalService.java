package ghidrassist.tools.approval;

import com.google.gson.JsonObject;
import ghidra.util.Msg;
import ghidrassist.chat.transcript.TranscriptService;
import ghidrassist.tools.api.Tool;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Session-scoped deterministic approval engine for tool execution.
 */
public class ToolApprovalService {
    public static final String TOOL_NAME_ALL = "*";
    public static final String SCOPE_SESSION = "session";
    public static final String DECISION_ALLOW_ONCE = "allow_once";
    public static final String DECISION_ALLOW_SESSION = "allow_session";
    public static final String DECISION_DENY = "deny";

    private final Connection connection;
    private final TranscriptService transcriptService;
    private final Map<String, PendingApproval> pendingApprovals = new ConcurrentHashMap<>();
    private volatile Runnable stateListener;

    public ToolApprovalService(Connection connection, TranscriptService transcriptService) {
        this.connection = connection;
        this.transcriptService = transcriptService;
    }

    public CompletableFuture<ApprovalOutcome> requestApproval(int sessionId, String programHash,
                                                              String correlationId, Tool tool, JsonObject args) {
        if (sessionId <= 0 || tool == null) {
            return CompletableFuture.completedFuture(ApprovalOutcome.approved(DECISION_ALLOW_ONCE));
        }

        ToolRiskTier riskTier = classify(tool);
        if (riskTier == ToolRiskTier.READ_ONLY) {
            return CompletableFuture.completedFuture(ApprovalOutcome.approved(DECISION_ALLOW_ONCE));
        }

        if (hasSessionGrant(sessionId, tool.getName())) {
            transcriptService.appendApprovalDecision(sessionId, programHash, correlationId, null, tool.getName(),
                "session grant reused", riskTier.name().toLowerCase(), SCOPE_SESSION, tool.getSource());
            return CompletableFuture.completedFuture(ApprovalOutcome.approved(DECISION_ALLOW_SESSION));
        }

        String requestId = java.util.UUID.randomUUID().toString();
        PendingApproval pending = new PendingApproval(
            requestId,
            sessionId,
            programHash,
            correlationId,
            tool.getName(),
            tool.getSource(),
            riskTier,
            args != null ? args.deepCopy() : new JsonObject()
        );
        pendingApprovals.put(requestId, pending);
        transcriptService.appendApprovalRequested(sessionId, programHash, correlationId, requestId,
            tool.getName(), tool.getSource(), riskTier.name().toLowerCase(), pending.args);
        notifyStateChanged();
        return pending.future;
    }

    public boolean resolvePendingApproval(String requestId, String decision) {
        PendingApproval pending = pendingApprovals.remove(requestId);
        if (pending == null) {
            return false;
        }

        String normalizedDecision = normalizeDecision(decision);
        if (DECISION_ALLOW_SESSION.equals(normalizedDecision)) {
            saveSessionGrant(pending.sessionId, pending.toolName, pending.riskTier);
        }

        transcriptService.appendApprovalDecision(
            pending.sessionId,
            pending.programHash,
            pending.correlationId,
            pending.requestId,
            pending.toolName,
            normalizedDecision,
            pending.riskTier.name().toLowerCase(),
            DECISION_ALLOW_SESSION.equals(normalizedDecision) ? SCOPE_SESSION : "once",
            pending.toolSource
        );

        pending.future.complete(DECISION_DENY.equals(normalizedDecision)
            ? ApprovalOutcome.denied(normalizedDecision)
            : ApprovalOutcome.approved(normalizedDecision));
        notifyStateChanged();
        return true;
    }

    public PendingApproval getFirstPendingApprovalForSession(int sessionId) {
        if (sessionId <= 0) {
            return null;
        }
        for (PendingApproval pending : pendingApprovals.values()) {
            if (pending.sessionId == sessionId) {
                return pending;
            }
        }
        return null;
    }

    public List<PendingApproval> getPendingApprovalsForSession(int sessionId) {
        List<PendingApproval> approvals = new ArrayList<>();
        if (sessionId <= 0) {
            return approvals;
        }
        for (PendingApproval pending : pendingApprovals.values()) {
            if (pending.sessionId == sessionId) {
                approvals.add(pending);
            }
        }
        return approvals;
    }

    public void setStateListener(Runnable stateListener) {
        this.stateListener = stateListener;
    }

    public void cancelPendingApprovalsForSession(int sessionId, String reason) {
        if (sessionId <= 0) {
            return;
        }
        List<String> toCancel = new ArrayList<>();
        for (PendingApproval pending : pendingApprovals.values()) {
            if (pending.sessionId == sessionId) {
                toCancel.add(pending.requestId);
            }
        }
        for (String requestId : toCancel) {
            PendingApproval pending = pendingApprovals.remove(requestId);
            if (pending != null) {
                transcriptService.appendApprovalDecision(
                    pending.sessionId,
                    pending.programHash,
                    pending.correlationId,
                    pending.requestId,
                    pending.toolName,
                    DECISION_DENY,
                    pending.riskTier.name().toLowerCase(),
                    "cancelled",
                    pending.toolSource
                );
                pending.future.complete(ApprovalOutcome.denied(reason != null ? reason : DECISION_DENY));
            }
        }
        if (!toCancel.isEmpty()) {
            notifyStateChanged();
        }
    }

    public ToolRiskTier classify(Tool tool) {
        String name = normalizeToolName(tool.getName());
        String source = tool.getSource() != null ? tool.getSource().toLowerCase() : "";

        if (source.startsWith("mcp:")) {
            if (looksReadOnly(name)) {
                return ToolRiskTier.READ_ONLY;
            }
            return ToolRiskTier.UNKNOWN;
        }

        if (name.contains("push") || name.contains("sync") || name.contains("upload")) {
            return ToolRiskTier.EXTERNAL;
        }
        if (name.contains("rename") || name.contains("retype") || name.contains("create")
            || name.contains("delete") || name.contains("patch") || name.contains("comment")
            || name.contains("set_") || name.startsWith("set") || name.contains("update")) {
            return ToolRiskTier.MUTATING;
        }
        if (looksReadOnly(name)) {
            return ToolRiskTier.READ_ONLY;
        }
        return ToolRiskTier.UNKNOWN;
    }

    private String normalizeDecision(String decision) {
        if (DECISION_ALLOW_SESSION.equals(decision)) {
            return DECISION_ALLOW_SESSION;
        }
        if (DECISION_ALLOW_ONCE.equals(decision)) {
            return DECISION_ALLOW_ONCE;
        }
        return DECISION_DENY;
    }

    private boolean looksReadOnly(String name) {
        return name.startsWith("get")
            || name.startsWith("list")
            || name.startsWith("query")
            || name.startsWith("search")
            || name.startsWith("lookup")
            || name.startsWith("fetch")
            || name.contains("current")
            || name.contains("semantic")
            || name.contains("graph")
            || name.contains("disasm")
            || name.contains("decomp");
    }

    private String normalizeToolName(String rawName) {
        String normalized = rawName != null ? rawName.toLowerCase() : "";
        int separator = normalized.lastIndexOf('.');
        if (separator >= 0 && separator + 1 < normalized.length()) {
            return normalized.substring(separator + 1);
        }
        return normalized;
    }

    private boolean hasSessionGrant(int sessionId, String toolName) {
        String sql = """
            SELECT 1 FROM GHChatApprovalGrants
            WHERE session_id = ? AND tool_name IN (?, ?) AND scope = ?
            LIMIT 1
        """;
        try (PreparedStatement stmt = connection.prepareStatement(sql)) {
            stmt.setInt(1, sessionId);
            stmt.setString(2, toolName);
            stmt.setString(3, TOOL_NAME_ALL);
            stmt.setString(4, SCOPE_SESSION);
            ResultSet rs = stmt.executeQuery();
            return rs.next();
        } catch (SQLException e) {
            Msg.warn(this, "Failed to load approval grant: " + e.getMessage());
            return false;
        }
    }

    public boolean isAcceptAllToolsEnabled(int sessionId) {
        if (sessionId <= 0) {
            return false;
        }
        return hasSessionGrant(sessionId, TOOL_NAME_ALL);
    }

    public void setAcceptAllToolsEnabled(int sessionId, boolean enabled) {
        if (sessionId <= 0) {
            return;
        }
        if (enabled) {
            saveSessionGrant(sessionId, TOOL_NAME_ALL, ToolRiskTier.UNKNOWN);
        } else {
            deleteSessionGrant(sessionId, TOOL_NAME_ALL);
        }
        notifyStateChanged();
    }

    private void saveSessionGrant(int sessionId, String toolName, ToolRiskTier riskTier) {
        String sql = """
            INSERT INTO GHChatApprovalGrants (session_id, tool_name, risk_tier, scope)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(session_id, tool_name) DO UPDATE SET
                risk_tier = excluded.risk_tier,
                scope = excluded.scope,
                created_at = CURRENT_TIMESTAMP
        """;
        try (PreparedStatement stmt = connection.prepareStatement(sql)) {
            stmt.setInt(1, sessionId);
            stmt.setString(2, toolName);
            stmt.setString(3, riskTier.name().toLowerCase());
            stmt.setString(4, SCOPE_SESSION);
            stmt.executeUpdate();
        } catch (SQLException e) {
            Msg.warn(this, "Failed to persist approval grant: " + e.getMessage());
        }
    }

    private void deleteSessionGrant(int sessionId, String toolName) {
        String sql = "DELETE FROM GHChatApprovalGrants WHERE session_id = ? AND tool_name = ?";
        try (PreparedStatement stmt = connection.prepareStatement(sql)) {
            stmt.setInt(1, sessionId);
            stmt.setString(2, toolName);
            stmt.executeUpdate();
        } catch (SQLException e) {
            Msg.warn(this, "Failed to delete approval grant: " + e.getMessage());
        }
    }

    private void notifyStateChanged() {
        Runnable listener = stateListener;
        if (listener != null) {
            listener.run();
        }
    }

    public static class ApprovalOutcome {
        private final boolean approved;
        private final String decision;

        private ApprovalOutcome(boolean approved, String decision) {
            this.approved = approved;
            this.decision = decision;
        }

        public static ApprovalOutcome approved(String decision) {
            return new ApprovalOutcome(true, decision);
        }

        public static ApprovalOutcome denied(String decision) {
            return new ApprovalOutcome(false, decision);
        }

        public boolean isApproved() {
            return approved;
        }

        public String getDecision() {
            return decision;
        }
    }

    public static class PendingApproval {
        private final String requestId;
        private final int sessionId;
        private final String programHash;
        private final String correlationId;
        private final String toolName;
        private final String toolSource;
        private final ToolRiskTier riskTier;
        private final JsonObject args;
        private final CompletableFuture<ApprovalOutcome> future = new CompletableFuture<>();

        public PendingApproval(String requestId, int sessionId, String programHash, String correlationId,
                               String toolName, String toolSource, ToolRiskTier riskTier, JsonObject args) {
            this.requestId = requestId;
            this.sessionId = sessionId;
            this.programHash = programHash;
            this.correlationId = correlationId;
            this.toolName = toolName;
            this.toolSource = toolSource;
            this.riskTier = riskTier;
            this.args = args != null ? args : new JsonObject();
        }

        public String getRequestId() {
            return requestId;
        }

        public int getSessionId() {
            return sessionId;
        }

        public String getProgramHash() {
            return programHash;
        }

        public String getCorrelationId() {
            return correlationId;
        }

        public String getToolName() {
            return toolName;
        }

        public String getToolSource() {
            return toolSource;
        }

        public ToolRiskTier getRiskTier() {
            return riskTier;
        }

        public JsonObject getArgs() {
            return args;
        }
    }
}
