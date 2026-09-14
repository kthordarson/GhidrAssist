package ghidrassist.ui.tabs;

import javax.swing.*;
import javax.swing.event.TableModelEvent;
import javax.swing.table.DefaultTableModel;
import javax.swing.text.*;
import javax.swing.text.html.HTML;
import javax.swing.text.html.HTMLDocument;
import javax.swing.text.html.HTMLEditorKit;
import java.awt.*;
import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.StringSelection;
import java.awt.event.ActionEvent;
import java.awt.event.ComponentAdapter;
import java.awt.event.ComponentEvent;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.io.StringWriter;
import java.text.SimpleDateFormat;
import java.util.TimeZone;
import java.util.Date;
import ghidra.util.Msg;
import ghidrassist.core.MarkdownHelper;
import ghidrassist.core.TabController;
import ghidrassist.core.streaming.RenderUpdate;
import ghidrassist.core.streaming.StreamingScrollManager;
import ghidrassist.mcp2.server.MCPServerRegistry;
import ghidrassist.AnalysisDB;
import ghidrassist.services.QueryService;

public class QueryTab extends JPanel {
    private static final long serialVersionUID = 1L;
    private static final String[] CHAT_TYPE_LABELS = {
        "Chat",
        "General",
        "Malware Report",
        "Vulnerability Analysis",
        "API Documentation",
        "Notes"
    };
    private final TabController controller;
    private final MarkdownHelper markdownHelper;
    private JTextPane responseTextPane;  // Changed from JEditorPane for better performance
    private StyledDocument responseDocument;
    private JTextArea queryTextArea;
    private JCheckBox useRAGCheckBox;
    private JCheckBox useMCPCheckBox;
    private JCheckBox useAgenticCheckBox;
    private JCheckBox acceptAllToolsCheckBox;
    private JButton submitButton;
    private JButton newButton;
    private JButton deleteButton;
    private JTable chatHistoryTable;
    private DefaultTableModel chatHistoryModel;
    private JLabel contextStatusLabel;
    private JPanel approvalPanel;
    private JPanel planPanel;
    private JTextArea planTextArea;
    private JButton approvePlanButton;
    private JButton cancelPlanButton;
    private JLabel approvalSummaryLabel;
    private JTextArea approvalArgsArea;
    private JButton approveOnceButton;
    private JButton approveSessionButton;
    private JButton denyApprovalButton;
    private String currentPendingApprovalRequestId;
    private SimpleDateFormat dateFormat;

    // Edit mode components
    private JButton editSaveButton;
    private JTextArea markdownEditArea;
    private JPanel contentPanel;
    private CardLayout contentLayout;
    private boolean isEditMode = false;
    private String currentMarkdownSource = "";
    private static final String QUERY_HINT_TEXT =
        "#line to include the current disassembly line.\n" +
        "#func to include current function disassembly.\n" +
        "#addr to include the current hex address.\n" +
        "#range(start, end) to include the view data in a given range.";

    // Use shared theme-aware CSS from MarkdownHelper for consistency
    private static String getStreamingCSS() {
        return MarkdownHelper.getThemeAwareCSS();
    }

    // Streaming state fields
    private StringBuilder accumulatedCommittedHtml = new StringBuilder();
    private String lastPendingHtml = "<span></span>";
    private boolean documentCorrupted = false;
    private String currentStreamingPrefixHtml = "";
    private String currentStreamingBodyPrefixHtml = "";
    private String currentStreamingBodySuffixHtml = "";
    private StreamingScrollManager scrollManager;
    private JScrollPane responseScrollPane;

    public QueryTab(TabController controller) {
        super(new BorderLayout());
        this.controller = controller;
        this.markdownHelper = new MarkdownHelper();
        this.dateFormat = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
        this.dateFormat.setTimeZone(TimeZone.getDefault()); // Use local timezone

        // Initialize JTextPane with StyledDocument for incremental updates
        responseTextPane = new JTextPane();
        responseTextPane.setEditable(false);
        responseDocument = responseTextPane.getStyledDocument();

        // Enable double buffering for smoother updates
        responseTextPane.setDoubleBuffered(true);

        initializeComponents();
        layoutComponents();
        setupListeners();
        setupMCPDetection();
        setupChatHistoryRefresh();
        setupContextMenu();
    }

    private void initializeComponents() {
        useRAGCheckBox = new JCheckBox("Use RAG");
        useRAGCheckBox.setSelected(false);

        useMCPCheckBox = new JCheckBox("Use MCP Tools");
        useMCPCheckBox.setSelected(false);
        useMCPCheckBox.setEnabled(false); // Disabled by default, enabled when MCP is detected

        useAgenticCheckBox = new JCheckBox("Agentic Mode (ReAct)");
        useAgenticCheckBox.setSelected(false);
        useAgenticCheckBox.setEnabled(false); // Enabled only when MCP is available
        useAgenticCheckBox.setToolTipText("Enable autonomous ReAct-style analysis with systematic tool use");

        acceptAllToolsCheckBox = new JCheckBox("Accept All Tools");
        acceptAllToolsCheckBox.setSelected(false);
        acceptAllToolsCheckBox.setEnabled(true);
        acceptAllToolsCheckBox.setToolTipText("Allow all tool calls for the active chat session without prompting");

        // responseTextPane already initialized in constructor

        queryTextArea = new JTextArea();
        queryTextArea.setRows(4);
        queryTextArea.setFont(new Font("Monospaced", Font.PLAIN, 12));
        queryTextArea.setLineWrap(true);
        queryTextArea.setWrapStyleWord(true);
        addHintTextToQueryTextArea();

        submitButton = new JButton("Submit");
        newButton = new JButton("New");
        deleteButton = new JButton("Delete");
        editSaveButton = new JButton("Edit");
        contextStatusLabel = new JLabel("Model: No provider / No model | No active context window data");
        contextStatusLabel.setFont(new Font("Monospaced", Font.PLAIN, 11));
        approvalPanel = new JPanel(new BorderLayout(6, 6));
        planPanel = new JPanel(new BorderLayout(6, 6));
        planTextArea = new JTextArea(5, 40);
        planTextArea.setEditable(false);
        planTextArea.setLineWrap(true);
        planTextArea.setWrapStyleWord(true);
        planTextArea.setFont(new Font("Monospaced", Font.PLAIN, 11));
        approvePlanButton = new JButton("Approve Plan");
        cancelPlanButton = new JButton("Cancel");
        approvalSummaryLabel = new JLabel(" ");
        approvalSummaryLabel.setFont(new Font("SansSerif", Font.PLAIN, 11));
        approvalArgsArea = new JTextArea(2, 40);
        approvalArgsArea.setEditable(false);
        approvalArgsArea.setLineWrap(true);
        approvalArgsArea.setWrapStyleWord(true);
        approvalArgsArea.setFont(new Font("Monospaced", Font.PLAIN, 11));
        approveOnceButton = new JButton("Allow Once");
        approveSessionButton = new JButton("Allow for Session");
        denyApprovalButton = new JButton("Deny");
        Font compactButtonFont = new Font("SansSerif", Font.PLAIN, 11);
        Insets compactButtonInsets = new Insets(4, 8, 4, 8);
        approveOnceButton.setFont(compactButtonFont);
        approveSessionButton.setFont(compactButtonFont);
        denyApprovalButton.setFont(compactButtonFont);
        approveOnceButton.setMargin(compactButtonInsets);
        approveSessionButton.setMargin(compactButtonInsets);
        denyApprovalButton.setMargin(compactButtonInsets);
        approvalPanel.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createLineBorder(new Color(180, 60, 60), 1),
            BorderFactory.createEmptyBorder(4, 6, 6, 6)
        ));
        planPanel.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createLineBorder(new Color(70, 130, 190), 1),
            BorderFactory.createEmptyBorder(4, 6, 6, 6)
        ));
        planTextArea.setBorder(BorderFactory.createEmptyBorder(4, 4, 4, 4));
        approvalArgsArea.setBorder(BorderFactory.createEmptyBorder(4, 4, 4, 4));
        approvalPanel.setVisible(false);
        planPanel.setVisible(false);

        // Initialize markdown edit area for edit mode
        markdownEditArea = new JTextArea();
        markdownEditArea.setFont(new Font("Monospaced", Font.PLAIN, 12));
        markdownEditArea.setLineWrap(true);
        markdownEditArea.setWrapStyleWord(true);

        // Setup card layout for switching between view and edit modes
        contentLayout = new CardLayout();
        contentPanel = new JPanel(contentLayout);

        // Initialize chat history table
        chatHistoryModel = new DefaultTableModel(new Object[]{"Description", "Date", "Type"}, 0) {
            private static final long serialVersionUID = 1L;
            @Override
            public boolean isCellEditable(int row, int column) {
                return column == 0 || column == 2;
            }
        };
        
        chatHistoryTable = new JTable(chatHistoryModel);
        chatHistoryTable.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);
        chatHistoryTable.setRowHeight(20);
        chatHistoryTable.setTableHeader(null); // Completely remove header row
        chatHistoryTable.getColumnModel().getColumn(2).setCellEditor(
                new DefaultCellEditor(new JComboBox<>(CHAT_TYPE_LABELS)));
        
        // Set column widths
        chatHistoryTable.getColumnModel().getColumn(0).setPreferredWidth(180); // Description
        chatHistoryTable.getColumnModel().getColumn(1).setPreferredWidth(130); // Date
        chatHistoryTable.getColumnModel().getColumn(2).setPreferredWidth(160); // Type
    }

    private void layoutComponents() {
        // Create top panel with checkboxes and edit button
        JPanel topPanel = new JPanel(new BorderLayout());

        JPanel checkboxPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        checkboxPanel.add(useRAGCheckBox);
        checkboxPanel.add(useMCPCheckBox);
        checkboxPanel.add(useAgenticCheckBox);
        checkboxPanel.add(acceptAllToolsCheckBox);
        topPanel.add(checkboxPanel, BorderLayout.CENTER);

        JPanel editPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        editPanel.add(editSaveButton);
        topPanel.add(editPanel, BorderLayout.EAST);

        JPanel statusPanel = new JPanel(new BorderLayout(0, 6));
        statusPanel.add(contextStatusLabel, BorderLayout.WEST);
        topPanel.add(statusPanel, BorderLayout.SOUTH);

        JPanel approvalButtonPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 4));
        approvalButtonPanel.add(approveOnceButton);
        approvalButtonPanel.add(approveSessionButton);
        approvalButtonPanel.add(denyApprovalButton);
        JPanel planButtonPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 4));
        planButtonPanel.add(approvePlanButton);
        planButtonPanel.add(cancelPlanButton);
        planPanel.add(new JLabel("Review the proposed investigation plan. Refine in the query box, or approve to run."),
            BorderLayout.NORTH);
        JScrollPane planScrollPane = new JScrollPane(planTextArea);
        planScrollPane.setBorder(BorderFactory.createEmptyBorder());
        planPanel.add(planScrollPane, BorderLayout.CENTER);
        planPanel.add(planButtonPanel, BorderLayout.SOUTH);
        approvalPanel.add(approvalSummaryLabel, BorderLayout.NORTH);
        JScrollPane approvalArgsScrollPane = new JScrollPane(approvalArgsArea);
        approvalArgsScrollPane.setBorder(BorderFactory.createEmptyBorder());
        approvalPanel.add(approvalArgsScrollPane, BorderLayout.CENTER);
        approvalPanel.add(approvalButtonPanel, BorderLayout.SOUTH);

        add(topPanel, BorderLayout.NORTH);

        // Setup content panel with CardLayout (view mode + edit mode)
        responseScrollPane = new JScrollPane(responseTextPane);
        responseScrollPane.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_ALWAYS);
        responseScrollPane.setHorizontalScrollBarPolicy(JScrollPane.HORIZONTAL_SCROLLBAR_NEVER);
        scrollManager = new StreamingScrollManager(responseScrollPane);
        JScrollPane editScrollPane = new JScrollPane(markdownEditArea);
        contentPanel.add(responseScrollPane, "view");
        contentPanel.add(editScrollPane, "edit");

        JScrollPane queryScrollPane = new JScrollPane(queryTextArea);

        // Create chat history scroll pane with default height of 2 rows
        JScrollPane chatHistoryScrollPane = new JScrollPane(chatHistoryTable);
        chatHistoryScrollPane.setPreferredSize(new Dimension(0, 50)); // About 2 rows height
        chatHistoryScrollPane.setMinimumSize(new Dimension(0, 40));

        // Create a panel for chat history and query area
        JPanel bottomPanel = new JPanel(new BorderLayout());
        bottomPanel.add(chatHistoryScrollPane, BorderLayout.NORTH);
        bottomPanel.add(queryScrollPane, BorderLayout.CENTER);

        JPanel responseAreaPanel = new JPanel(new BorderLayout());
        responseAreaPanel.add(contentPanel, BorderLayout.CENTER);
        JPanel inlinePanel = new JPanel();
        inlinePanel.setLayout(new BoxLayout(inlinePanel, BoxLayout.Y_AXIS));
        inlinePanel.add(planPanel);
        inlinePanel.add(approvalPanel);
        responseAreaPanel.add(inlinePanel, BorderLayout.SOUTH);

        // Create main split pane between response/approval and (chat history + query)
        JSplitPane mainSplitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT,
            responseAreaPanel, bottomPanel);
        mainSplitPane.setResizeWeight(0.7); // Give more space to response area

        // Create inner split pane for chat history and query area
        JSplitPane bottomSplitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT,
            chatHistoryScrollPane, queryScrollPane);
        bottomSplitPane.setResizeWeight(0.3); // Chat history takes less space than query

        // Replace the bottom panel with the split pane
        bottomPanel.removeAll();
        bottomPanel.add(bottomSplitPane, BorderLayout.CENTER);

        add(mainSplitPane, BorderLayout.CENTER);

        JPanel buttonPanel = new JPanel();
        buttonPanel.add(submitButton);
        buttonPanel.add(newButton);
        buttonPanel.add(deleteButton);
        add(buttonPanel, BorderLayout.SOUTH);
    }

    private void setupListeners() {
        // Add hyperlink listener for RLHF feedback buttons
        responseTextPane.addHyperlinkListener(controller::handleHyperlinkEvent);

        submitButton.addActionListener(e -> controller.handleQuerySubmit(
            queryTextArea.getText(),
            useRAGCheckBox.isSelected(),
            useMCPCheckBox.isSelected(),
            useAgenticCheckBox.isSelected()
        ));

        newButton.addActionListener(e -> controller.handleNewChatSession());

        deleteButton.addActionListener(e -> controller.handleDeleteCurrentSession());

        // Edit/Save button handler
        editSaveButton.addActionListener(e -> {
            if (isEditMode) {
                // Save mode - capture content and notify controller
                currentMarkdownSource = markdownEditArea.getText();
                boolean saved = controller.handleChatEditSave(currentMarkdownSource);
                if (!saved) {
                    return;
                }

                // Switch to view mode
                contentLayout.show(contentPanel, "view");
                editSaveButton.setText("Edit");
                isEditMode = false;
            } else {
                // Edit mode - notify controller to prepare content
                boolean success = controller.handleChatEditStart();
                if (!success) {
                    return; // Don't enter edit mode if preparation failed
                }

                // Switch to edit mode
                contentLayout.show(contentPanel, "edit");
                editSaveButton.setText("Save");
                isEditMode = true;
            }
        });

        approveOnceButton.addActionListener(e -> controller.handleApprovalDecision(
            currentPendingApprovalRequestId, "allow_once"));
        approveSessionButton.addActionListener(e -> controller.handleApprovalDecision(
            currentPendingApprovalRequestId, "allow_session"));
        denyApprovalButton.addActionListener(e -> controller.handleApprovalDecision(
            currentPendingApprovalRequestId, "deny"));
        approvePlanButton.addActionListener(e -> controller.handleAgentPlanApproved());
        cancelPlanButton.addActionListener(e -> controller.handleAgentPlanCancelled());
        acceptAllToolsCheckBox.addActionListener(e ->
            controller.handleAcceptAllToolsChanged(acceptAllToolsCheckBox.isSelected()));

        // ESC key discards edits and returns to view mode
        markdownEditArea.getInputMap(JComponent.WHEN_FOCUSED)
            .put(KeyStroke.getKeyStroke("ESCAPE"), "cancelEdit");
        markdownEditArea.getActionMap().put("cancelEdit", new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent ae) {
                if (isEditMode) {
                    contentLayout.show(contentPanel, "view");
                    editSaveButton.setText("Edit");
                    isEditMode = false;
                }
            }
        });

        // Chat history table selection listener
        chatHistoryTable.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                int selectedRow = chatHistoryTable.getSelectedRow();
                if (selectedRow >= 0) {
                    controller.handleChatSessionSelection(selectedRow);
                }
            }
        });
        
        // Chat history table double-click for inline editing
        chatHistoryTable.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                if (e.getClickCount() == 2) {
                    int row = chatHistoryTable.rowAtPoint(e.getPoint());
                    int col = chatHistoryTable.columnAtPoint(e.getPoint());
                    if (row >= 0 && col == 0) { // Only description column is editable
                        chatHistoryTable.editCellAt(row, col);
                    }
                }
            }
        });
        
        // Auto-save when focus changes from description field
        chatHistoryModel.addTableModelListener(e -> {
            if (e.getType() != TableModelEvent.UPDATE) {
                return;
            }

            int row = e.getFirstRow();
            if (row >= 0) {
                if (e.getColumn() == 0) {
                    String newDescription = (String) chatHistoryModel.getValueAt(row, 0);
                    controller.handleChatDescriptionUpdate(row, newDescription);
                } else if (e.getColumn() == 2) {
                    String newType = (String) chatHistoryModel.getValueAt(row, 2);
                    controller.handleChatTypeUpdate(row, newType);
                }
            }
        });
    }

    private void addHintTextToQueryTextArea() {
        Color fgColor = queryTextArea.getForeground();
        queryTextArea.setText(QUERY_HINT_TEXT);
        queryTextArea.setForeground(Color.GRAY);
        
        queryTextArea.addFocusListener(new java.awt.event.FocusAdapter() {
            @Override
            public void focusGained(java.awt.event.FocusEvent e) {
                if (queryTextArea.getText().equals(QUERY_HINT_TEXT)) {
                    queryTextArea.setText("");
                    queryTextArea.setForeground(fgColor);
                }
            }

            @Override
            public void focusLost(java.awt.event.FocusEvent e) {
                if (queryTextArea.getText().isEmpty()) {
                    queryTextArea.setForeground(Color.GRAY);
                    queryTextArea.setText(QUERY_HINT_TEXT);
                }
            }
        });
    }

    /**
     * Set response text - switches to HTML mode and renders full content.
     * PERFORMANCE: This is used at completion for full markdown rendering.
     * Preserves scroll position if user has scrolled up from bottom.
     */
    public void setResponseText(String htmlText) {
        Runnable updateUi = () -> {
            try {
                // Capture scroll state BEFORE any modifications
                boolean wasAtBottom = scrollManager.isAtBottom();
                int savedScrollValue = scrollManager.getScrollPane().getVerticalScrollBar().getValue();

                // Switch to HTML mode for final markdown rendering
                responseTextPane.setContentType("text/html");
                responseTextPane.setEditorKit(new HTMLEditorKit());
                responseTextPane.setText(htmlText);

                // Restore scroll position - only auto-scroll if user was at bottom
                SwingUtilities.invokeLater(() -> {
                    if (wasAtBottom) {
                        scrollManager.scrollToBottom();
                    } else {
                        scrollManager.getScrollPane().getVerticalScrollBar().setValue(savedScrollValue);
                    }
                });
            } catch (Exception e) {
                Msg.error(this, "Error setting response text", e);
            }
        };

        if (SwingUtilities.isEventDispatchThread()) {
            updateUi.run();
        } else {
            SwingUtilities.invokeLater(updateUi);
        }
    }

    /**
     * Initialize the response pane for streaming with a two-div DOM structure.
     * Optionally includes conversation history as a prefix.
     *
     * @param prefixHtml Pre-rendered HTML for conversation history (may be empty)
     */
    public void initializeForStreaming(String prefixHtml) {
        initializeForStreaming(prefixHtml, "", "");
    }

    public void initializeForStreaming(String prefixHtml, String bodyPrefixHtml, String bodySuffixHtml) {
        Runnable initializeUi = () -> {
            // Capture scroll state BEFORE any modifications
            boolean wasAtBottom = scrollManager.isAtBottom();
            int savedScrollValue = scrollManager.getScrollPane().getVerticalScrollBar().getValue();

            // Reset streaming state
            accumulatedCommittedHtml.setLength(0);
            lastPendingHtml = "<span></span>";
            documentCorrupted = false;
            currentStreamingPrefixHtml = (prefixHtml != null && !prefixHtml.isEmpty()) ? prefixHtml : "";
            currentStreamingBodyPrefixHtml = bodyPrefixHtml != null ? bodyPrefixHtml : "";
            currentStreamingBodySuffixHtml = bodySuffixHtml != null ? bodySuffixHtml : "";

            // Switch to HTML mode
            responseTextPane.setContentType("text/html");
            HTMLEditorKit kit = new HTMLEditorKit();
            responseTextPane.setEditorKit(kit);

            // Build initial HTML with two-div structure
            String initialHtml = String.format(
                "<html><head><style>%s</style></head><body>%s%s" +
                "<div id=\"committed\"></div>" +
                "<div id=\"pending\"><span></span></div>" +
                "%s</body></html>",
                getStreamingCSS(), currentStreamingPrefixHtml, currentStreamingBodyPrefixHtml,
                currentStreamingBodySuffixHtml);

            responseTextPane.setText(initialHtml);
            responseDocument = responseTextPane.getStyledDocument();

            // Restore scroll position
            if (wasAtBottom) {
                SwingUtilities.invokeLater(() -> scrollManager.scrollToBottom());
            } else {
                SwingUtilities.invokeLater(() ->
                        scrollManager.getScrollPane().getVerticalScrollBar().setValue(savedScrollValue));
            }
        };

        if (SwingUtilities.isEventDispatchThread()) {
            initializeUi.run();
        } else {
            SwingUtilities.invokeLater(initializeUi);
        }
    }

    public void updateStreamingPrefix(String prefixHtml) {
        Runnable updateUi = () -> {
            currentStreamingPrefixHtml = prefixHtml != null ? prefixHtml : "";
            rebuildDocument();
        };

        if (SwingUtilities.isEventDispatchThread()) {
            updateUi.run();
        } else {
            SwingUtilities.invokeLater(updateUi);
        }
    }

    /**
     * Apply a render update to the streaming display.
     * Handles both incremental (append/replace) and full document replacement.
     * Note: This method is called from EDT (via StreamingMarkdownRenderer's invokeLater).
     *
     * @param update The render update to apply
     */
    public void applyRenderUpdate(RenderUpdate update) {
        if (update == null) {
            return;
        }

        // Capture scroll state BEFORE any DOM modification
        boolean wasAtBottom = scrollManager.isAtBottom();
        int savedScrollValue = scrollManager.getScrollPane().getVerticalScrollBar().getValue();

        // Apply the update
        switch (update.getType()) {
            case INCREMENTAL -> applyIncrementalUpdate(update);
            case FULL_REPLACE -> applyFullReplaceUpdate(update);
        }

        // Restore scroll position or auto-scroll (matching reference implementation)
        if (wasAtBottom) {
            SwingUtilities.invokeLater(() -> scrollManager.scrollToBottom());
        } else {
            // Restore the user's scroll position exactly
            SwingUtilities.invokeLater(() ->
                    scrollManager.getScrollPane().getVerticalScrollBar().setValue(savedScrollValue));
        }
    }

    private void applyIncrementalUpdate(RenderUpdate update) {
        // Track content for fallback rebuilds
        String committedHtml = update.getCommittedHtmlToAppend();
        if (committedHtml != null && !committedHtml.isEmpty()) {
            accumulatedCommittedHtml.append(committedHtml);
        }
        String pendingHtml = update.getPendingHtml();
        if (pendingHtml != null) {
            lastPendingHtml = pendingHtml;
        }

        // If document was previously corrupted, use full rebuild strategy
        if (documentCorrupted) {
            rebuildDocument();
            return;
        }

        HTMLDocument doc = ensureHtmlDocument();
        if (doc == null) {
            documentCorrupted = true;
            rebuildDocument();
            return;
        }

        try {
            // Append committed HTML
            if (committedHtml != null && !committedHtml.isEmpty()) {
                Element committedDiv = findElement(doc, "committed");
                if (committedDiv != null) {
                    doc.insertBeforeEnd(committedDiv, committedHtml);
                }
            }

            // Replace pending div atomically using setOuterHTML
            // (avoids the BiDi corruption bug in setInnerHTML)
            if (pendingHtml != null) {
                Element pendingDiv = findElement(doc, "pending");
                if (pendingDiv != null) {
                    String wrappedPending = "<div id=\"pending\">" + pendingHtml + "</div>";
                    doc.setOuterHTML(pendingDiv, wrappedPending);
                }
            }
        } catch (Exception e) {
            Msg.warn(this, "DOM update failed, switching to rebuild strategy: " + e.getMessage());
            documentCorrupted = true;
            rebuildDocument();
        }
    }

    private void applyFullReplaceUpdate(RenderUpdate update) {
        String fullHtml = update.getFullHtml();
        if (fullHtml != null) {
            String wrapped = "<html><head><style>" + getStreamingCSS() + "</style></head><body>" +
                    currentStreamingPrefixHtml +
                    currentStreamingBodyPrefixHtml +
                    fullHtml + "</body></html>";
            wrapped = wrapped.replace("</body></html>", currentStreamingBodySuffixHtml + "</body></html>");
            responseTextPane.setContentType("text/html");
            responseTextPane.setEditorKit(new HTMLEditorKit());
            responseTextPane.setText(wrapped);
            documentCorrupted = false;
        }
    }

    private void rebuildDocument() {
        String html = "<html><head><style>" + getStreamingCSS() + "</style></head><body>" +
                currentStreamingPrefixHtml +
                currentStreamingBodyPrefixHtml +
                accumulatedCommittedHtml.toString() +
                lastPendingHtml +
                currentStreamingBodySuffixHtml +
                "</body></html>";
        responseTextPane.setContentType("text/html");
        responseTextPane.setEditorKit(new HTMLEditorKit());
        responseTextPane.setText(html);
    }

    /**
     * Ensure the response pane has an HTMLDocument.
     * When streaming starts before HTML initialization finishes, Swing may still
     * expose a DefaultStyledDocument. Recover by rebuilding the HTML document.
     */
    private HTMLDocument ensureHtmlDocument() {
        Document currentDoc = responseTextPane.getDocument();
        if (currentDoc instanceof HTMLDocument) {
            return (HTMLDocument) currentDoc;
        }

        Msg.warn(this, "Query response document is not HTMLDocument (" +
                currentDoc.getClass().getName() + "); rebuilding HTML view.");

        responseTextPane.setContentType("text/html");
        responseTextPane.setEditorKit(new HTMLEditorKit());
        String repairedHtml = "<html><head><style>" + getStreamingCSS() + "</style></head><body>" +
                currentStreamingPrefixHtml +
                currentStreamingBodyPrefixHtml +
                "<div id=\"committed\">" + accumulatedCommittedHtml + "</div>" +
                "<div id=\"pending\">" + lastPendingHtml + "</div>" +
                currentStreamingBodySuffixHtml +
                "</body></html>";
        responseTextPane.setText(repairedHtml);

        Document repairedDoc = responseTextPane.getDocument();
        if (repairedDoc instanceof HTMLDocument) {
            return (HTMLDocument) repairedDoc;
        }

        Msg.error(this, "Failed to recover HTMLDocument for query streaming", null);
        return null;
    }

    private Element findElement(HTMLDocument doc, String id) {
        return findElementById(doc.getDefaultRootElement(), id);
    }

    private Element findElementById(Element element, String id) {
        // Check this element's attributes for an id
        Object idAttr = element.getAttributes().getAttribute(HTML.Attribute.ID);
        if (id.equals(idAttr)) {
            return element;
        }

        // Recursively search children
        for (int i = 0; i < element.getElementCount(); i++) {
            Element found = findElementById(element.getElement(i), id);
            if (found != null) {
                return found;
            }
        }
        return null;
    }

    /**
     * Clear the response and prepare for streaming.
     */
    public void clearResponse() {
        initializeForStreaming("");
    }

    public void appendToResponse(String html) {
        // For backward compatibility - now just sets text
        setResponseText(html);
    }
    
    public void setSubmitButtonText(String text) {
        submitButton.setText(text);
    }
    
    public void setMCPEnabled(boolean enabled) {
        useMCPCheckBox.setEnabled(enabled);
        // Agentic mode requires MCP tools, so enable/disable together
        useAgenticCheckBox.setEnabled(enabled);
    }

    public boolean isMCPEnabled() {
        return useMCPCheckBox.isEnabled();
    }

    public boolean isMCPSelected() {
        return useMCPCheckBox.isSelected();
    }

    public boolean isAgenticSelected() {
        return useAgenticCheckBox.isSelected();
    }
    
    /**
     * Setup chat history refresh when tab receives focus
     */
    private void setupChatHistoryRefresh() {
        // Refresh chat history when tab receives focus
        this.addFocusListener(new java.awt.event.FocusAdapter() {
            @Override
            public void focusGained(java.awt.event.FocusEvent e) {
                controller.refreshChatHistory();
            }
        });
        
        // Also refresh when component becomes visible
        this.addComponentListener(new ComponentAdapter() {
            @Override
            public void componentShown(ComponentEvent e) {
                controller.refreshChatHistory();
            }
        });
    }
    
    /**
     * Setup MCP detection that checks for availability when tab becomes visible
     */
    private void setupMCPDetection() {
        // Check MCP availability when component becomes visible
        this.addComponentListener(new ComponentAdapter() {
            @Override
            public void componentShown(ComponentEvent e) {
                updateMCPCheckboxState();
            }
        });
        
        // Also check when gaining focus
        this.addFocusListener(new java.awt.event.FocusAdapter() {
            @Override
            public void focusGained(java.awt.event.FocusEvent e) {
                updateMCPCheckboxState();
            }
        });
        
        // Initial check
        SwingUtilities.invokeLater(this::updateMCPCheckboxState);
    }
    
    /**
     * Update MCP checkbox state based on enabled server configuration
     * Checks if any MCP servers are configured and enabled
     */
    private void updateMCPCheckboxState() {
        if (!SwingUtilities.isEventDispatchThread()) {
            SwingUtilities.invokeLater(this::updateMCPCheckboxState);
            return;
        }

        // Check if any MCP servers are enabled in configuration
        MCPServerRegistry registry = MCPServerRegistry.getInstance();
        boolean hasEnabledServers = !registry.getEnabledServers().isEmpty();

        boolean wasEnabled = useMCPCheckBox.isEnabled();
        useMCPCheckBox.setEnabled(hasEnabledServers);

        // Agentic mode requires MCP, so enable/disable together
        useAgenticCheckBox.setEnabled(hasEnabledServers);

        // If no servers enabled, also uncheck both boxes
        if (!hasEnabledServers) {
            useMCPCheckBox.setSelected(false);
            useAgenticCheckBox.setSelected(false);
        }
        
        // Log state change for debugging
        if (wasEnabled != hasEnabledServers) {
            String state = hasEnabledServers ? "enabled" : "disabled";
            int enabledCount = registry.getEnabledServers().size();
            Msg.info(this, "MCP Tools checkbox " + state + " - enabled servers: " + enabledCount);
        }
    }
    
    /**
     * Public method to update MCP checkbox state
     * Called by controller when actions are triggered
     */
    public void refreshMCPState() {
        updateMCPCheckboxState();
    }
    
    /**
     * Update the chat history table with sessions
     */
    public void updateChatHistory(java.util.List<AnalysisDB.ChatSession> sessions) {
        chatHistoryModel.setRowCount(0); // Clear existing rows
        
        for (AnalysisDB.ChatSession session : sessions) {
            // Convert SQL Timestamp to Date and format in local timezone
            String formattedDate = "-";
            if (session.getLastUpdate() != null) {
                Date localDate = new Date(session.getLastUpdate().getTime());
                formattedDate = dateFormat.format(localDate);
            }
            chatHistoryModel.addRow(new Object[]{
                session.getDescription(),
                formattedDate,
                toDisplayChatType(session.getChatType())
            });
        }
    }

    private String toDisplayChatType(String chatType) {
        if (chatType == null) {
            return "Chat";
        }

        return switch (chatType) {
            case "general" -> "General";
            case "malware_report" -> "Malware Report";
            case "vuln_analysis" -> "Vulnerability Analysis";
            case "api_doc", "protocol_spec" -> "API Documentation";
            case "notes" -> "Notes";
            default -> "Chat";
        };
    }
    
    /**
     * Select a specific chat session row
     */
    public void selectChatSession(int rowIndex) {
        if (rowIndex >= 0 && rowIndex < chatHistoryTable.getRowCount()) {
            chatHistoryTable.setRowSelectionInterval(rowIndex, rowIndex);
        }
    }
    
    /**
     * Clear chat history selection
     */
    public void clearChatSelection() {
        chatHistoryTable.clearSelection();
    }
    
    /**
     * Get the currently selected chat session row (first selected if multiple)
     */
    public int getSelectedChatSession() {
        return chatHistoryTable.getSelectedRow();
    }

    /**
     * Get all selected chat session rows (for bulk operations like delete)
     */
    public int[] getSelectedChatSessions() {
        return chatHistoryTable.getSelectedRows();
    }

    /**
     * Setup context menu for clipboard operations
     */
    private void setupContextMenu() {
        JPopupMenu contextMenu = new JPopupMenu();

        JMenuItem copyMarkdown = new JMenuItem("Copy as Markdown");
        copyMarkdown.addActionListener(e -> {
            String selectedText = isEditMode ?
                    markdownEditArea.getSelectedText() :
                    getSelectedMarkdownText();
            if (selectedText != null && !selectedText.isEmpty()) {
                copyToClipboard(selectedText);
            }
        });

        JMenuItem copyHtml = new JMenuItem("Copy as HTML");
        copyHtml.addActionListener(e -> {
            if (isEditMode) {
                String selectedText = markdownEditArea.getSelectedText();
                if (selectedText != null && !selectedText.isEmpty()) {
                    copyToClipboard(selectedText);
                }
            } else {
                int start = responseTextPane.getSelectionStart();
                int end = responseTextPane.getSelectionEnd();
                if (start != end) {
                    String html = extractSelectedHtml(start, end);
                    if (html != null && !html.isEmpty()) {
                        copyToClipboard(html);
                    }
                }
            }
        });

        JMenuItem copyPlainText = new JMenuItem("Copy as Plain Text");
        copyPlainText.addActionListener(e -> {
            String selectedText = isEditMode ?
                    markdownEditArea.getSelectedText() :
                    responseTextPane.getSelectedText();
            if (selectedText != null && !selectedText.isEmpty()) {
                copyToClipboard(selectedText);
            }
        });

        JMenuItem copyAll = new JMenuItem("Copy All as Markdown");
        copyAll.addActionListener(e -> {
            copyToClipboard(currentMarkdownSource);
        });

        JMenuItem selectAll = new JMenuItem("Select All");
        selectAll.addActionListener(e -> {
            if (isEditMode) {
                markdownEditArea.selectAll();
            } else {
                responseTextPane.selectAll();
            }
        });

        JMenuItem paste = new JMenuItem("Paste");
        paste.addActionListener(e -> {
            if (isEditMode) {
                markdownEditArea.paste();
            }
        });

        contextMenu.add(copyMarkdown);
        contextMenu.add(copyHtml);
        contextMenu.add(copyPlainText);
        contextMenu.addSeparator();
        contextMenu.add(copyAll);
        contextMenu.add(selectAll);
        contextMenu.addSeparator();
        contextMenu.add(paste);

        // Show paste only in edit mode
        contextMenu.addPopupMenuListener(new javax.swing.event.PopupMenuListener() {
            @Override
            public void popupMenuWillBecomeVisible(javax.swing.event.PopupMenuEvent e) {
                paste.setEnabled(isEditMode);
            }
            @Override
            public void popupMenuWillBecomeInvisible(javax.swing.event.PopupMenuEvent e) {}
            @Override
            public void popupMenuCanceled(javax.swing.event.PopupMenuEvent e) {}
        });

        responseTextPane.setComponentPopupMenu(contextMenu);
        markdownEditArea.setComponentPopupMenu(contextMenu);

        // Override CTRL-C to copy markdown from view mode
        responseTextPane.getActionMap().put("copy", new AbstractAction() {
            private static final long serialVersionUID = 1L;
            @Override
            public void actionPerformed(ActionEvent e) {
                String md = getSelectedMarkdownText();
                if (md != null && !md.isEmpty()) {
                    copyToClipboard(md);
                }
            }
        });
    }

    /**
     * Get selected markdown text based on selection in view mode.
     * Maps the rendered plain text selection back to the corresponding lines
     * in the markdown source by stripping markdown formatting for comparison.
     * Returns null if nothing is selected.
     */
    private String getSelectedMarkdownText() {
        String selectedText = responseTextPane.getSelectedText();
        if (selectedText == null || selectedText.isEmpty()) {
            return null;
        }
        if (currentMarkdownSource == null || currentMarkdownSource.isEmpty()) {
            return selectedText;
        }
        return mapRenderedTextToMarkdown(selectedText, currentMarkdownSource);
    }

    /**
     * Map rendered plain text back to the corresponding region in the markdown source.
     *
     * Builds a single normalized plain-text document from the markdown (stripping all
     * formatting), then finds the normalized selection text within it as a contiguous
     * substring. This avoids false matches from short individual lines like "Summary"
     * matching unrelated lines containing that word.
     *
     * Once the match position is found, it maps back to the original markdown line
     * numbers and returns those lines with formatting preserved.
     */
    private static String mapRenderedTextToMarkdown(String renderedText, String markdownSource) {
        String[] mdLines = markdownSource.split("\\n", -1);

        // Strip each markdown line and build a single normalized document,
        // tracking which markdown line each character range came from.
        String[] strippedLines = new String[mdLines.length];
        for (int i = 0; i < mdLines.length; i++) {
            strippedLines[i] = stripMarkdownFormatting(mdLines[i]).trim();
        }

        StringBuilder docBuilder = new StringBuilder();
        int[] lineDocStart = new int[mdLines.length];
        int[] lineDocEnd = new int[mdLines.length];
        for (int i = 0; i < mdLines.length; i++) {
            lineDocStart[i] = -1;
            lineDocEnd[i] = -1;
        }

        for (int i = 0; i < strippedLines.length; i++) {
            if (strippedLines[i].isEmpty()) continue;
            if (docBuilder.length() > 0) {
                docBuilder.append(' ');
            }
            lineDocStart[i] = docBuilder.length();
            docBuilder.append(strippedLines[i]);
            lineDocEnd[i] = docBuilder.length();
        }

        // Normalize both selection and document: collapse all whitespace to single space
        String normalizedSelection = renderedText.replaceAll("\\s+", " ").trim();
        if (normalizedSelection.isEmpty()) {
            return renderedText;
        }
        String normalizedDoc = docBuilder.toString();

        // Find the full selection in the stripped document
        int matchPos = normalizedDoc.indexOf(normalizedSelection);

        // If exact match fails, try a shorter leading prefix (selection boundary may
        // have clipped a word)
        if (matchPos < 0 && normalizedSelection.length() > 40) {
            matchPos = normalizedDoc.indexOf(normalizedSelection.substring(0, 40));
        }

        if (matchPos >= 0) {
            int matchEnd = Math.min(matchPos + normalizedSelection.length(), normalizedDoc.length());

            // Find the markdown lines whose stripped text overlaps the match range
            int startLine = -1;
            int endLine = -1;
            for (int i = 0; i < mdLines.length; i++) {
                if (lineDocStart[i] == -1) continue; // empty line
                if (lineDocEnd[i] > matchPos && lineDocStart[i] < matchEnd) {
                    if (startLine == -1) startLine = i;
                    endLine = i;
                }
            }

            if (startLine >= 0 && endLine >= startLine) {
                StringBuilder result = new StringBuilder();
                for (int i = startLine; i <= endLine; i++) {
                    if (i > startLine) result.append('\n');
                    result.append(mdLines[i]);
                }
                return result.toString();
            }
        }

        // Fallback: return the plain text selection
        return renderedText;
    }

    /**
     * Strip markdown formatting from a line for plain-text comparison.
     * Removes headers, bold, italic, code, links, list markers, blockquotes, etc.
     */
    private static String stripMarkdownFormatting(String line) {
        String s = line;
        s = s.replaceAll("^#{1,6}\\s+", "");
        s = s.replaceAll("\\*\\*(.+?)\\*\\*", "$1");
        s = s.replaceAll("__(.+?)__", "$1");
        s = s.replaceAll("\\*(.+?)\\*", "$1");
        s = s.replaceAll("(?<=\\s|^)_(.+?)_(?=\\s|$)", "$1");
        s = s.replaceAll("`([^`]+)`", "$1");
        s = s.replaceAll("\\[([^\\]]+)\\]\\([^)]+\\)", "$1");
        s = s.replaceAll("!\\[([^\\]]*)]\\([^)]+\\)", "$1");
        s = s.replaceAll("^\\s*[-*+]\\s+", "");
        s = s.replaceAll("^\\s*\\d+\\.\\s+", "");
        s = s.replaceAll("^>+\\s?", "");
        s = s.replaceAll("~~(.+?)~~", "$1");
        return s;
    }

    /**
     * Extract HTML content for the selected range from the JTextPane's document.
     */
    private String extractSelectedHtml(int start, int end) {
        try {
            Document doc = responseTextPane.getDocument();
            if (doc instanceof HTMLDocument) {
                HTMLEditorKit kit = new HTMLEditorKit();
                StringWriter writer = new StringWriter();
                kit.write(writer, doc, start, end - start);
                return writer.toString();
            }
            // Fallback for non-HTML documents
            return responseTextPane.getSelectedText();
        } catch (Exception e) {
            Msg.warn(this, "Failed to extract HTML: " + e.getMessage());
            return responseTextPane.getSelectedText();
        }
    }

    /**
     * Copy text to system clipboard
     */
    private void copyToClipboard(String text) {
        if (text != null && !text.isEmpty()) {
            try {
                Clipboard clipboard = Toolkit.getDefaultToolkit().getSystemClipboard();
                clipboard.setContents(new StringSelection(text), null);
            } catch (Exception e) {
                Msg.error(this, "Failed to copy to clipboard: " + e.getMessage());
            }
        }
    }

    // Edit mode public methods

    /**
     * Set editable content for edit mode
     */
    public void setEditableContent(String markdown) {
        currentMarkdownSource = markdown;
        markdownEditArea.setText(markdown);
        markdownEditArea.setCaretPosition(0);
    }

    /**
     * Get the current editable content
     */
    public String getEditableContent() {
        return isEditMode ? markdownEditArea.getText() : currentMarkdownSource;
    }

    /**
     * Set the markdown source (for view mode)
     */
    public void setMarkdownSource(String markdown) {
        currentMarkdownSource = markdown;
    }

    /**
     * Get the current markdown source
     */
    public String getMarkdownSource() {
        return currentMarkdownSource;
    }

    /**
     * Check if currently in edit mode
     */
    public boolean isInEditMode() {
        return isEditMode;
    }

    /**
     * Exit edit mode without saving
     */
    public void exitEditMode() {
        if (isEditMode) {
            contentLayout.show(contentPanel, "view");
            editSaveButton.setText("Edit");
            isEditMode = false;
        }
    }

    public void setEditEnabled(boolean enabled) {
        if (!enabled) {
            exitEditMode();
        }
        editSaveButton.setEnabled(enabled);
        editSaveButton.setToolTipText(enabled
            ? "Edit the most recent assistant response"
            : "No assistant response is available to edit yet.");
    }

    public void setContextStatus(String contextStatus) {
        String text = contextStatus != null && !contextStatus.isBlank()
            ? contextStatus
            : "Model: No provider / No model | No active context window data";
        if (SwingUtilities.isEventDispatchThread()) {
            contextStatusLabel.setText(text);
        } else {
            SwingUtilities.invokeLater(() -> contextStatusLabel.setText(text));
        }
    }

    public void setPendingApproval(QueryService.PendingApprovalView pendingApproval) {
        Runnable updateUi = () -> {
            currentPendingApprovalRequestId = pendingApproval != null ? pendingApproval.getRequestId() : null;
            if (pendingApproval == null) {
                approvalPanel.setVisible(false);
                approvalSummaryLabel.setText(" ");
                approvalArgsArea.setText("");
                approvalPanel.revalidate();
                approvalPanel.repaint();
                return;
            }

            approvalSummaryLabel.setText(String.format(
                "Approval required: %s [%s] from %s",
                pendingApproval.getToolName(),
                pendingApproval.getRiskTier().name().toLowerCase(),
                pendingApproval.getToolSource()
            ));
            approvalArgsArea.setText(pendingApproval.getArgsPreview());
            approvalArgsArea.setCaretPosition(0);
            approvalPanel.setVisible(true);
            approvalPanel.revalidate();
            approvalPanel.repaint();
        };

        if (SwingUtilities.isEventDispatchThread()) {
            updateUi.run();
        } else {
            SwingUtilities.invokeLater(updateUi);
        }
    }

    public void setPendingPlan(String planMarkdown) {
        Runnable updateUi = () -> {
            if (planMarkdown == null || planMarkdown.isBlank()) {
                planPanel.setVisible(false);
                planTextArea.setText("");
            } else {
                planTextArea.setText(planMarkdown);
                planTextArea.setCaretPosition(0);
                planPanel.setVisible(true);
            }
            planPanel.revalidate();
            planPanel.repaint();
        };

        if (SwingUtilities.isEventDispatchThread()) {
            updateUi.run();
        } else {
            SwingUtilities.invokeLater(updateUi);
        }
    }

    public void setAcceptAllToolsState(boolean enabled, boolean selected) {
        Runnable updateUi = () -> {
            // Keep this interactive like the MCP/ReAct toggles. The controller
            // will create a session on demand when the user enables it.
            acceptAllToolsCheckBox.setEnabled(true);
            acceptAllToolsCheckBox.setSelected(selected);
        };
        if (SwingUtilities.isEventDispatchThread()) {
            updateUi.run();
        } else {
            SwingUtilities.invokeLater(updateUi);
        }
    }

    /**
     * Get the MarkdownHelper instance
     */
    public MarkdownHelper getMarkdownHelper() {
        return markdownHelper;
    }

}
