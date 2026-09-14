package ghidrassist.chat.transcript;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import ghidrassist.core.MarkdownHelper;

import java.sql.Timestamp;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

/**
 * Renders transcript events into a structured HTML timeline for the Query pane.
 */
public class TranscriptRenderer {
    private static final SimpleDateFormat TIMESTAMP_FORMAT =
        new SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.US);
    private static final Gson PRETTY_GSON = new GsonBuilder().setPrettyPrinting().create();

    private final MarkdownHelper markdownHelper = new MarkdownHelper();
    private final Set<String> expandedToolGroups = new HashSet<>();
    private final Set<Long> expandedTodoCards = new HashSet<>();

    public String renderDocument(List<TranscriptEvent> events) {
        return wrap(renderFragment(events), true);
    }

    public String renderStreamingAssistantCardPrefix(Timestamp timestamp) {
        return startCardTable("Assistant", accentColor(TranscriptEventKind.ASSISTANT_MESSAGE),
            "Assistant", timestamp, null, null);
    }

    public String renderStreamingAssistantCardSuffix() {
        return endCardTable();
    }

    public String renderFragment(List<TranscriptEvent> events) {
        StringBuilder html = new StringBuilder();
        html.append("<div class='ga-transcript'>");
        Set<String> renderedCorrelationIds = new HashSet<>();

        for (TranscriptEvent event : events) {
            if (isGroupedToolEvent(event) && event.getCorrelationId() != null) {
                if (renderedCorrelationIds.add(event.getCorrelationId())) {
                    html.append(renderToolGroup(collectByCorrelation(events, event.getCorrelationId())));
                }
            } else {
                html.append(renderSingleCard(event));
            }
        }

        html.append("</div>");
        return html.toString();
    }

    private String wrap(String body, boolean includeFeedback) {
        StringBuilder html = new StringBuilder();
        html.append("<html><head><style>");
        html.append(MarkdownHelper.getThemeAwareCSS());
        html.append(".ga-transcript{margin:0;padding:0;width:100%;}");
        html.append(".ga-card-table{width:100%;margin:8px 0;border-collapse:collapse;table-layout:fixed;border:1px solid #5a636c;}");
        html.append(".ga-meta{font-size:9px;color:#777;}");
        html.append(".ga-body{padding:8px;width:100%;}");
        html.append(".ga-block{margin-top:6px;}");
        html.append(".ga-block-title{font-weight:bold;margin-bottom:3px;font-size:10px;}");
        html.append(".ga-code{font-family:monospace;font-size:9px;white-space:pre-wrap;word-wrap:break-word;overflow-wrap:anywhere;}");
        html.append(".ga-tool-summary{font-size:10px;line-height:1.35;}");
        html.append(".ga-tool-summary b{font-weight:bold;}");
        html.append(".ga-toggle{font-size:9px;margin-top:6px;}");
        html.append("</style></head><body>");
        html.append(body);
        if (includeFeedback) {
            html.append("<br><div style=\"text-align:center;color:grey;font-size:18px;\">");
            html.append("<a href='thumbsup'>&#10004;</a> | <a href='thumbsdown'>&#10006;</a></div>");
        }
        html.append("</body></html>");
        return html.toString();
    }

    private String renderToolGroup(List<TranscriptEvent> group) {
        TranscriptEvent requested = findFirst(group, TranscriptEventKind.TOOL_CALL_REQUESTED);
        TranscriptEvent started = findFirst(group, TranscriptEventKind.TOOL_CALL_STARTED);
        TranscriptEvent completed = findFirst(group, TranscriptEventKind.TOOL_CALL_COMPLETED);
        TranscriptEvent failed = findFirst(group, TranscriptEventKind.TOOL_CALL_FAILED);
        TranscriptEvent approvalRequested = findFirst(group, TranscriptEventKind.APPROVAL_REQUESTED);
        TranscriptEvent approvalDecision = findFirst(group, TranscriptEventKind.APPROVAL_DECISION);

        JsonObject requestedMeta = parseMetadata(requested != null ? requested : approvalRequested);
        JsonObject approvalMeta = parseMetadata(approvalRequested);
        JsonObject decisionMeta = parseMetadata(approvalDecision);

        String toolName = firstNonBlank(
            getString(requestedMeta, "tool"),
            getString(approvalMeta, "tool"),
            requested != null ? requested.getTitle() : null,
            approvalRequested != null ? approvalRequested.getTitle() : null,
            "Tool"
        );
        String source = firstNonBlank(getString(requestedMeta, "source"), getString(approvalMeta, "source"), "unknown");
        String riskTier = firstNonBlank(getString(approvalMeta, "risk_tier"), getString(decisionMeta, "risk_tier"), null);
        String correlationId = group.get(0).getCorrelationId();
        boolean expanded = correlationId != null && expandedToolGroups.contains(correlationId);
        StringBuilder card = new StringBuilder();
        card.append(startCardTable("Tool", "#7a5b18", toolName, group.get(0).getCreatedAt(), source, riskTier));

        String decision = approvalRequested != null
            ? (approvalDecision != null ? firstNonBlank(
                getString(decisionMeta, "decision"),
                approvalDecision.getContentText()
            ) : "pending")
            : null;
        String argsPreview = requested != null
            ? firstNonBlank(requested.getPreviewText(), resolveArgsPreview(requestedMeta))
            : null;
        String executionPreview = started != null ? started.getContentText() : null;
        String resultPreview = completed != null ? resolveBody(completed) : (failed != null ? resolveBody(failed) : null);

        card.append(compactToolSummary(decision, argsPreview, executionPreview, resultPreview, failed != null));

        if (expanded) {
            if (approvalRequested != null) {
                card.append(section("Approval", "Status: " + decision + "\nArguments: " + approvalRequested.getPreviewText()));
            }
            if (argsPreview != null && !argsPreview.isBlank()) {
                card.append(section("Arguments", argsPreview));
            }
            if (started != null) {
                card.append(section("Execution", started.getContentText()));
            }
            if (completed != null) {
                card.append(section("Result", resolveBody(completed)));
                if (completed.getArtifactId() != null && !completed.getArtifactId().isBlank()) {
                    card.append(section("Artifact", completed.getArtifactId()));
                }
            } else if (failed != null) {
                card.append(section("Failure", resolveBody(failed)));
            }
        }

        if (correlationId != null) {
            card.append(toggleLink(correlationId, expanded));
        }

        card.append(endCardTable());
        return card.toString();
    }

    private String renderSingleCard(TranscriptEvent event) {
        StringBuilder card = new StringBuilder();
        card.append(startCardTable(kindLabel(event.getKind()), accentColor(event.getKind()),
            event.getTitle(), event.getCreatedAt(), null, null));

        String body = resolveBody(event);
        if (event.getKind() == TranscriptEventKind.TODO_UPDATED) {
            card.append(renderTodoSnapshot(event));
        } else if (event.getKind() == TranscriptEventKind.CONTEXT_COMPACTED) {
            JsonObject metadata = parseMetadata(event);
            if (metadata != null && !metadata.entrySet().isEmpty()) {
                card.append(section("Compaction Summary", body));
                card.append(section("Details", formatCompactionMetadata(metadata)));
            } else {
                card.append(sectionHtml(markdownHelper.markdownToHtmlFragment(body != null ? body : "")));
            }
        } else if (usesMarkdown(event.getKind())) {
            card.append(sectionHtml(markdownHelper.markdownToHtmlFragment(body != null ? body : "")));
        } else {
            card.append(section(null, body));
        }

        if (event.getArtifactId() != null && !event.getArtifactId().isBlank()) {
            card.append(section("Artifact", event.getArtifactId()));
        }

        card.append(endCardTable());
        return card.toString();
    }

    private boolean isGroupedToolEvent(TranscriptEvent event) {
        return event.getKind() == TranscriptEventKind.TOOL_CALL_REQUESTED
            || event.getKind() == TranscriptEventKind.TOOL_CALL_STARTED
            || event.getKind() == TranscriptEventKind.TOOL_CALL_COMPLETED
            || event.getKind() == TranscriptEventKind.TOOL_CALL_FAILED
            || event.getKind() == TranscriptEventKind.APPROVAL_REQUESTED
            || event.getKind() == TranscriptEventKind.APPROVAL_DECISION;
    }

    private List<TranscriptEvent> collectByCorrelation(List<TranscriptEvent> events, String correlationId) {
        List<TranscriptEvent> group = new ArrayList<>();
        for (TranscriptEvent event : events) {
            if (correlationId.equals(event.getCorrelationId())) {
                group.add(event);
            }
        }
        return group;
    }

    private TranscriptEvent findFirst(List<TranscriptEvent> group, TranscriptEventKind kind) {
        for (TranscriptEvent event : group) {
            if (event.getKind() == kind) {
                return event;
            }
        }
        return null;
    }

    private boolean usesMarkdown(TranscriptEventKind kind) {
        return kind == TranscriptEventKind.USER_MESSAGE
            || kind == TranscriptEventKind.ASSISTANT_MESSAGE
            || kind == TranscriptEventKind.FINDING_ADDED
            || kind == TranscriptEventKind.DOCUMENT_SNAPSHOT
            || kind == TranscriptEventKind.CONTEXT_COMPACTED;
    }

    private String accentColor(TranscriptEventKind kind) {
        return switch (kind) {
            case USER_MESSAGE -> "#4c79d7";
            case ASSISTANT_MESSAGE, DOCUMENT_SNAPSHOT -> "#2e8b57";
            case APPROVAL_REQUESTED, APPROVAL_DECISION -> "#b85c28";
            case TODO_UPDATED -> "#8066cc";
            case FINDING_ADDED -> "#a26b00";
            case ITERATION_NOTICE -> "#5c6f82";
            case CONTEXT_COMPACTED -> "#6b46c1";
            case SYSTEM_NOTICE -> "#666666";
            default -> "#666666";
        };
    }

    private String resolveBody(TranscriptEvent event) {
        if (event.getContentText() != null && !event.getContentText().isBlank()) {
            return event.getContentText();
        }
        if (event.getPreviewText() != null) {
            return event.getPreviewText();
        }
        return "";
    }

    private String resolveArgsPreview(JsonObject metadata) {
        if (metadata == null) {
            return null;
        }
        JsonElement args = metadata.get("args");
        return args != null ? args.toString() : null;
    }

    private String kindLabel(TranscriptEventKind kind) {
        return switch (kind) {
            case USER_MESSAGE -> "User";
            case ASSISTANT_MESSAGE -> "Assistant";
            case TOOL_CALL_REQUESTED -> "Tool Requested";
            case TOOL_CALL_STARTED -> "Tool Running";
            case TOOL_CALL_COMPLETED -> "Tool Result";
            case TOOL_CALL_FAILED -> "Tool Failed";
            case APPROVAL_REQUESTED -> "Approval Requested";
            case APPROVAL_DECISION -> "Approval Decision";
            case TODO_UPDATED -> "Tasks";
            case FINDING_ADDED -> "Finding";
            case ITERATION_NOTICE -> "Agent";
            case CONTEXT_COMPACTED -> "Context Compacted";
            case SYSTEM_NOTICE -> "System";
            case DOCUMENT_SNAPSHOT -> "Document Snapshot";
        };
    }

    private JsonObject parseMetadata(TranscriptEvent event) {
        if (event == null || event.getMetadataJson() == null || event.getMetadataJson().isBlank()) {
            return null;
        }
        try {
            return JsonParser.parseString(event.getMetadataJson()).getAsJsonObject();
        } catch (Exception ignored) {
            return null;
        }
    }

    private String getString(JsonObject metadata, String key) {
        if (metadata == null || key == null || !metadata.has(key) || metadata.get(key).isJsonNull()) {
            return null;
        }
        return metadata.get(key).getAsString();
    }

    private String formatCompactionMetadata(JsonObject metadata) {
        List<String> lines = new ArrayList<>();
        String provider = getString(metadata, "provider");
        String model = getString(metadata, "model");
        if (provider != null || model != null) {
            lines.add("Model: " + firstNonBlank(provider, "unknown") + " / " + firstNonBlank(model, "unknown"));
        }
        if (metadata.has("original_message_count") || metadata.has("final_message_count")) {
            lines.add("Messages: "
                + firstNonBlank(getString(metadata, "original_message_count"), "?")
                + " -> "
                + firstNonBlank(getString(metadata, "final_message_count"), "?"));
        }
        if (metadata.has("current_tokens") || metadata.has("max_tokens")) {
            lines.add("Tokens: "
                + firstNonBlank(getString(metadata, "current_tokens"), "?")
                + " / "
                + firstNonBlank(getString(metadata, "max_tokens"), "?"));
        }
        if (metadata.has("threshold_tokens")) {
            lines.add("Compression threshold: " + firstNonBlank(getString(metadata, "threshold_tokens"), "?"));
        }
        if (lines.isEmpty()) {
            return metadata.toString();
        }
        return String.join("\n", lines);
    }

    private String firstNonBlank(String... values) {
        for (String value : values) {
            if (value != null && !value.isBlank()) {
                return value;
            }
        }
        return null;
    }

    private String startCardTable(String badge, String accentColor, String title, Timestamp timestamp,
                                  String source, String riskTier) {
        StringBuilder html = new StringBuilder();
        html.append("<table class='ga-card-table' cellspacing='0' cellpadding='0' width='100%'>");
        html.append("<tr><td bgcolor='").append(accentColor)
            .append("' width='8' valign='top'>&nbsp;</td>");
        html.append("<td class='ga-body' width='100%'>");
        html.append("<div><b>").append(escapeHtml(badge)).append("</b>");
        if (title != null && !title.isBlank()) {
            html.append(" <span>").append(escapeHtml(title)).append("</span>");
        }
        html.append("</div>");
        html.append("<div class='ga-meta'>").append(escapeHtml(formatTimestamp(timestamp)));
        if (source != null && !source.isBlank()) {
            html.append(" | ").append(escapeHtml(source));
        }
        if (riskTier != null && !riskTier.isBlank()) {
            html.append(" | ").append(escapeHtml(riskTier));
        }
        html.append("</div>");
        return html.toString();
    }

    private String section(String label, String content) {
        StringBuilder html = new StringBuilder();
        html.append("<div class='ga-block'>");
        if (label != null && !label.isBlank()) {
            html.append("<div class='ga-block-title'>").append(escapeHtml(label)).append("</div>");
        }
        html.append("<div class='ga-code'>")
            .append(escapePreservingWhitespace(formatStructuredText(content)))
            .append("</div></div>");
        return html.toString();
    }

    private String sectionHtml(String htmlContent) {
        return "<div style='margin-top:8px;'>" + (htmlContent != null ? htmlContent : "") + "</div>";
    }

    public void toggleToolGroup(String correlationId) {
        if (correlationId == null || correlationId.isBlank()) {
            return;
        }
        if (!expandedToolGroups.add(correlationId)) {
            expandedToolGroups.remove(correlationId);
        }
    }

    public void toggleTodoCard(long eventId) {
        if (eventId <= 0) {
            return;
        }
        if (!expandedTodoCards.add(eventId)) {
            expandedTodoCards.remove(eventId);
        }
    }

    private String endCardTable() {
        return "</td></tr></table>";
    }

    private String formatTimestamp(Timestamp timestamp) {
        return timestamp != null ? TIMESTAMP_FORMAT.format(timestamp) : "";
    }

    private String escapeHtml(String value) {
        if (value == null) {
            return "";
        }
        return value
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace("\"", "&quot;");
    }

    private String escapePreservingWhitespace(String value) {
        String escaped = escapeHtml(value != null ? value : "");
        return escaped
            .replace("\t", "    ")
            .replace("\r\n", "\n")
            .replace("\n", "<br>");
    }

    private String formatStructuredText(String content) {
        if (content == null || content.isBlank()) {
            return "";
        }
        String trimmed = content.trim();
        if (!(trimmed.startsWith("{") || trimmed.startsWith("["))) {
            return content;
        }
        try {
            JsonElement parsed = JsonParser.parseString(trimmed);
            return PRETTY_GSON.toJson(parsed);
        } catch (Exception ignored) {
            return content;
        }
    }

    private String compactToolSummary(String decision, String argsPreview, String executionPreview,
                                      String resultPreview, boolean failed) {
        StringBuilder html = new StringBuilder();
        html.append("<div class='ga-tool-summary'>");
        if (decision != null && !decision.isBlank()) {
            html.append("<div><b>Approval:</b> ").append(escapeHtml(decision)).append("</div>");
        }
        if (argsPreview != null && !argsPreview.isBlank()) {
            html.append("<div><b>Args:</b> ")
                .append(escapeHtml(compactPreview(argsPreview, 140)))
                .append("</div>");
        }
        if (executionPreview != null && !executionPreview.isBlank()) {
            html.append("<div><b>Status:</b> ").append(escapeHtml(compactPreview(executionPreview, 80))).append("</div>");
        }
        if (resultPreview != null && !resultPreview.isBlank()) {
            html.append("<div><b>").append(failed ? "Failure" : "Result").append(":</b> ")
                .append(escapeHtml(compactPreview(summarizeStructuredText(resultPreview), 180)))
                .append("</div>");
        }
        html.append("</div>");
        return html.toString();
    }

    private String renderTodoSnapshot(TranscriptEvent event) {
        JsonObject metadata = parseMetadata(event);
        boolean expanded = expandedTodoCards.contains(event.getId());
        StringBuilder html = new StringBuilder();
        html.append("<div class='ga-tool-summary'>");
        html.append("<div><b>Summary:</b> ")
            .append(escapeHtml(firstNonBlank(
                getString(metadata, "summary"),
                compactPreview(event.getPreviewText(), 120),
                "Task list updated")))
            .append("</div>");
        if (metadata != null) {
            String counts = formatTodoCounts(metadata);
            if (counts != null) {
                html.append("<div><b>Progress:</b> ").append(escapeHtml(counts)).append("</div>");
            }
            String activeTask = findActiveTodo(metadata);
            if (activeTask != null) {
                html.append("<div><b>Active:</b> ").append(escapeHtml(activeTask)).append("</div>");
            }
        }
        html.append("</div>");
        if (expanded && metadata != null) {
            html.append(section("Tasks", formatTodoDetails(metadata)));
        }
        html.append(todoToggleLink(event.getId(), expanded));
        return html.toString();
    }

    private String formatTodoCounts(JsonObject metadata) {
        if (metadata == null) {
            return null;
        }
        int total = getInt(metadata, "total_count");
        int complete = getInt(metadata, "complete_count");
        int inProgress = getInt(metadata, "in_progress_count");
        int pending = getInt(metadata, "pending_count");
        if (total <= 0) {
            return null;
        }
        return complete + "/" + total + " complete"
            + " | " + inProgress + " active"
            + " | " + pending + " pending";
    }

    private String findActiveTodo(JsonObject metadata) {
        if (metadata == null || !metadata.has("todos") || !metadata.get("todos").isJsonArray()) {
            return null;
        }
        for (JsonElement element : metadata.getAsJsonArray("todos")) {
            if (!element.isJsonObject()) {
                continue;
            }
            JsonObject todo = element.getAsJsonObject();
            if ("IN_PROGRESS".equalsIgnoreCase(getString(todo, "status"))) {
                return getString(todo, "task");
            }
        }
        return null;
    }

    private String formatTodoDetails(JsonObject metadata) {
        if (metadata == null || !metadata.has("todos") || !metadata.get("todos").isJsonArray()) {
            return "";
        }
        List<String> lines = new ArrayList<>();
        for (JsonElement element : metadata.getAsJsonArray("todos")) {
            if (!element.isJsonObject()) {
                continue;
            }
            JsonObject todo = element.getAsJsonObject();
            String status = firstNonBlank(getString(todo, "status"), "PENDING");
            String icon = switch (status) {
                case "COMPLETE" -> "[x]";
                case "IN_PROGRESS" -> "[->]";
                default -> "[ ]";
            };
            StringBuilder line = new StringBuilder();
            line.append(icon).append(" ").append(firstNonBlank(getString(todo, "task"), "Unnamed task"));
            String evidence = getString(todo, "evidence");
            if (evidence != null && !evidence.isBlank()) {
                line.append("\n    evidence: ").append(evidence);
            }
            lines.add(line.toString());
        }
        return String.join("\n", lines);
    }

    private String todoToggleLink(long eventId, boolean expanded) {
        String action = expanded ? "todo-collapse:" : "todo-expand:";
        String label = expanded ? "Hide tasks" : "Show tasks";
        return "<div class='ga-toggle'><a href='" + action + eventId + "'>" + label + "</a></div>";
    }

    private String toggleLink(String correlationId, boolean expanded) {
        String action = expanded ? "tool-collapse:" : "tool-expand:";
        String label = expanded ? "Hide details" : "Show details";
        return "<div class='ga-toggle'><a href='" + action + escapeHtml(correlationId) + "'>"
            + label + "</a></div>";
    }

    private String compactPreview(String content, int maxLength) {
        if (content == null) {
            return "";
        }
        String normalized = summarizeStructuredText(content)
            .replace('\n', ' ')
            .replace('\r', ' ')
            .replaceAll("\\s+", " ")
            .trim();
        if (normalized.length() <= maxLength) {
            return normalized;
        }
        return normalized.substring(0, Math.max(0, maxLength - 3)) + "...";
    }

    private String summarizeStructuredText(String content) {
        if (content == null || content.isBlank()) {
            return "";
        }
        String trimmed = content.trim();
        if (!(trimmed.startsWith("{") || trimmed.startsWith("["))) {
            return content;
        }
        try {
            JsonElement parsed = JsonParser.parseString(trimmed);
            if (parsed.isJsonObject()) {
                JsonObject obj = parsed.getAsJsonObject();
                List<String> parts = new ArrayList<>();
                addSummaryPart(parts, "name", getString(obj, "name"));
                addSummaryPart(parts, "address", getString(obj, "address"));
                addSummaryPart(parts, "status", getString(obj, "status"));
                addSummaryPart(parts, "source_type", getString(obj, "source_type"));
                addSummaryPart(parts, "signature", getString(obj, "signature"));
                if (!parts.isEmpty()) {
                    return String.join(", ", parts);
                }
            }
            return PRETTY_GSON.toJson(parsed);
        } catch (Exception ignored) {
            return content;
        }
    }

    private void addSummaryPart(List<String> parts, String key, String value) {
        if (value != null && !value.isBlank()) {
            parts.add(key + "=" + value);
        }
    }

    private int getInt(JsonObject metadata, String key) {
        if (metadata == null || key == null || !metadata.has(key) || metadata.get(key).isJsonNull()) {
            return 0;
        }
        try {
            return metadata.get(key).getAsInt();
        } catch (Exception ignored) {
            return 0;
        }
    }
}
