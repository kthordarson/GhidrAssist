package ghidrassist.ui.tabs;

import javax.swing.*;
import javax.swing.border.TitledBorder;
import javax.swing.text.Element;
import javax.swing.text.html.HTML;
import javax.swing.text.html.HTMLDocument;
import javax.swing.text.html.HTMLEditorKit;
import java.awt.*;
import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.StringSelection;
import java.awt.event.ActionEvent;
import java.io.StringWriter;
import java.util.List;
import ghidra.util.Msg;
import ghidrassist.core.MarkdownHelper;
import ghidrassist.core.TabController;
import ghidrassist.core.streaming.RenderUpdate;
import ghidrassist.core.streaming.StreamingScrollManager;

public class ExplainTab extends JPanel {
    private static final long serialVersionUID = 1L;
    private final TabController controller;
    private final MarkdownHelper markdownHelper;
    private JLabel offsetLabel;
    private JTextField offsetField;
    private JEditorPane explainTextPane;
    private JTextArea markdownTextArea;
    private JButton explainFunctionButton;
    private JButton explainLineButton;
    private JButton clearExplainButton;
    private JButton editSaveButton;
    private JPanel contentPanel;
    private CardLayout contentLayout;
    private boolean isEditMode = false;
    private String currentMarkdown = "";

    // Security info panel components
    private JPanel securityInfoPanel;
    private JLabel riskLevelLabel;
    private JLabel categoryLabel;
    private JLabel activityProfileLabel;
    private JLabel securityFlagsLabel;
    private JTextArea networkAPIsTextArea;
    private JTextArea fileIOAPIsTextArea;

    // Line explanation panel components
    private JPanel lineExplanationPanel;
    private JEditorPane lineExplanationTextPane;
    private String lineExplanationMarkdown = "";
    private JSplitPane mainSplitPane;
    private JSplitPane outerSplitPane;
    private JButton lineExplanationCloseButton;

    // Use shared theme-aware CSS from MarkdownHelper
    private static String getStreamingCSS() {
        return MarkdownHelper.getThemeAwareCSS();
    }

    // Streaming state for function explanation pane
    private StringBuilder accumulatedCommittedHtml = new StringBuilder();
    private String lastPendingHtml = "<span></span>";
    private boolean documentCorrupted = false;
    private StreamingScrollManager scrollManager;
    private JScrollPane explainScrollPane;

    // Streaming state for line explanation pane
    private StringBuilder lineAccumulatedCommittedHtml = new StringBuilder();
    private String lineLastPendingHtml = "<span></span>";
    private boolean lineDocumentCorrupted = false;
    private StreamingScrollManager lineScrollManager;
    private JScrollPane lineExplanationScrollPane;

    public ExplainTab(TabController controller) {
        super(new BorderLayout());
        this.controller = controller;
        this.markdownHelper = new MarkdownHelper();
        initializeComponents();
        layoutComponents();
        setupListeners();
        setupContextMenu();
    }

    private void initializeComponents() {
        // Initialize offset field
        offsetLabel = new JLabel("Offset: ");
        offsetField = new JTextField(16);
        offsetField.setEditable(false);

        // Initialize text pane for HTML viewing
        explainTextPane = new JEditorPane();
        explainTextPane.setEditable(false);
        explainTextPane.setContentType("text/html");
        explainTextPane.addHyperlinkListener(controller::handleHyperlinkEvent);

        // Initialize text area for Markdown editing
        markdownTextArea = new JTextArea();
        markdownTextArea.setFont(new Font("Monospaced", Font.PLAIN, 12));
        markdownTextArea.setLineWrap(true);
        markdownTextArea.setWrapStyleWord(true);

        // Initialize buttons
        explainFunctionButton = new JButton("Explain Function");
        explainLineButton = new JButton("Explain Line");
        explainLineButton.setEnabled(true);
        explainLineButton.setToolTipText("Explain the current line at cursor position");
        clearExplainButton = new JButton("Clear");
        editSaveButton = new JButton("Edit");

        // Setup card layout for switching between view and edit modes
        contentLayout = new CardLayout();
        contentPanel = new JPanel(contentLayout);
        explainScrollPane = new JScrollPane(explainTextPane);
        explainScrollPane.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_ALWAYS);
        scrollManager = new StreamingScrollManager(explainScrollPane);
        contentPanel.add(explainScrollPane, "view");
        contentPanel.add(new JScrollPane(markdownTextArea), "edit");

        // Initialize security info panel
        securityInfoPanel = new JPanel();
        securityInfoPanel.setLayout(new BoxLayout(securityInfoPanel, BoxLayout.Y_AXIS));
        securityInfoPanel.setBorder(BorderFactory.createTitledBorder(
                BorderFactory.createEtchedBorder(), "Security Analysis",
                TitledBorder.LEFT, TitledBorder.TOP));

        // Risk level, category, and activity profile row
        JPanel topRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 10, 2));
        riskLevelLabel = new JLabel("Risk: —");
        riskLevelLabel.setFont(riskLevelLabel.getFont().deriveFont(Font.BOLD));
        categoryLabel = new JLabel("Category: —");
        activityProfileLabel = new JLabel("Activity: —");
        topRow.add(riskLevelLabel);
        topRow.add(categoryLabel);
        topRow.add(activityProfileLabel);
        securityInfoPanel.add(topRow);

        // Security flags row (BorderLayout so the label fills width and HTML wraps)
        JPanel flagsRow = new JPanel(new BorderLayout());
        flagsRow.setBorder(BorderFactory.createEmptyBorder(2, 10, 2, 10));
        securityFlagsLabel = new JLabel("<html>Flags: None</html>");
        flagsRow.add(securityFlagsLabel, BorderLayout.CENTER);
        securityInfoPanel.add(flagsRow);

        // API lists in a horizontal panel
        JPanel apiPanel = new JPanel(new GridLayout(1, 2, 10, 0));

        // Network APIs
        JPanel networkPanel = new JPanel(new BorderLayout());
        networkPanel.setBorder(BorderFactory.createTitledBorder("Network APIs"));
        networkAPIsTextArea = new JTextArea(3, 20);
        networkAPIsTextArea.setEditable(false);
        networkAPIsTextArea.setFont(new Font("Monospaced", Font.PLAIN, 11));
        networkPanel.add(new JScrollPane(networkAPIsTextArea), BorderLayout.CENTER);
        apiPanel.add(networkPanel);

        // File I/O APIs
        JPanel filePanel = new JPanel(new BorderLayout());
        filePanel.setBorder(BorderFactory.createTitledBorder("File I/O APIs"));
        fileIOAPIsTextArea = new JTextArea(3, 20);
        fileIOAPIsTextArea.setEditable(false);
        fileIOAPIsTextArea.setFont(new Font("Monospaced", Font.PLAIN, 11));
        filePanel.add(new JScrollPane(fileIOAPIsTextArea), BorderLayout.CENTER);
        apiPanel.add(filePanel);

        securityInfoPanel.add(apiPanel);

        // Initially hide the security panel until we have data
        securityInfoPanel.setVisible(false);

        // Initialize line explanation panel with header containing close button
        lineExplanationPanel = new JPanel(new BorderLayout());
        lineExplanationPanel.setBorder(BorderFactory.createEtchedBorder());

        // Create header panel with title and close button
        JPanel lineHeaderPanel = new JPanel(new BorderLayout());
        lineHeaderPanel.setBorder(BorderFactory.createEmptyBorder(2, 5, 2, 2));
        JLabel lineHeaderLabel = new JLabel("Line Explanation");
        lineHeaderLabel.setFont(lineHeaderLabel.getFont().deriveFont(Font.BOLD));
        lineHeaderPanel.add(lineHeaderLabel, BorderLayout.WEST);

        // Close button (small X)
        lineExplanationCloseButton = new JButton("\u00D7"); // Unicode multiplication sign as X
        lineExplanationCloseButton.setMargin(new Insets(0, 4, 0, 4));
        lineExplanationCloseButton.setFont(lineExplanationCloseButton.getFont().deriveFont(Font.BOLD, 14f));
        lineExplanationCloseButton.setFocusPainted(false);
        lineExplanationCloseButton.setBorderPainted(false);
        lineExplanationCloseButton.setContentAreaFilled(false);
        lineExplanationCloseButton.setToolTipText("Hide line explanation");
        lineExplanationCloseButton.addActionListener(e -> clearLineExplanation());
        lineHeaderPanel.add(lineExplanationCloseButton, BorderLayout.EAST);

        lineExplanationPanel.add(lineHeaderPanel, BorderLayout.NORTH);

        lineExplanationTextPane = new JEditorPane();
        lineExplanationTextPane.setEditable(false);
        lineExplanationTextPane.setContentType("text/html");
        lineExplanationTextPane.addHyperlinkListener(controller::handleHyperlinkEvent);

        lineExplanationScrollPane = new JScrollPane(lineExplanationTextPane);
        lineExplanationScrollPane.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_ALWAYS);
        lineExplanationScrollPane.setPreferredSize(new Dimension(0, 150));
        lineExplanationScrollPane.setMinimumSize(new Dimension(0, 80));
        lineScrollManager = new StreamingScrollManager(lineExplanationScrollPane);
        lineExplanationPanel.add(lineExplanationScrollPane, BorderLayout.CENTER);

        // Set preferred/minimum sizes for the panel
        lineExplanationPanel.setPreferredSize(new Dimension(0, 180));
        lineExplanationPanel.setMinimumSize(new Dimension(0, 100));

        // Initially hide the line explanation panel
        lineExplanationPanel.setVisible(false);
    }

    private void layoutComponents() {
        // Offset and Edit/Save panel
        JPanel topPanel = new JPanel(new BorderLayout());

        JPanel offsetPanel = new JPanel();
        offsetPanel.add(offsetLabel);
        offsetPanel.add(offsetField);
        topPanel.add(offsetPanel, BorderLayout.WEST);

        JPanel editPanel = new JPanel();
        editPanel.add(editSaveButton);
        topPanel.add(editPanel, BorderLayout.EAST);

        add(topPanel, BorderLayout.NORTH);

        // Create split pane with function explanation (top) and line explanation (bottom)
        mainSplitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
        mainSplitPane.setTopComponent(contentPanel);
        mainSplitPane.setBottomComponent(lineExplanationPanel);
        mainSplitPane.setResizeWeight(1.0); // Give all extra space to top component
        mainSplitPane.setOneTouchExpandable(true);
        mainSplitPane.setContinuousLayout(true);

        // Initially hide bottom component (line explanation)
        mainSplitPane.setDividerSize(0);
        mainSplitPane.setBottomComponent(null);

        // Outer split pane: mainSplitPane (top) / securityInfoPanel (bottom)
        outerSplitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
        outerSplitPane.setTopComponent(mainSplitPane);
        outerSplitPane.setBottomComponent(securityInfoPanel);
        outerSplitPane.setResizeWeight(1.0); // Main content gets extra space
        outerSplitPane.setOneTouchExpandable(true);
        outerSplitPane.setContinuousLayout(true);

        add(outerSplitPane, BorderLayout.CENTER);

        // Button panel directly in SOUTH (no wrapper)
        JPanel buttonPanel = new JPanel();
        buttonPanel.add(explainFunctionButton);
        buttonPanel.add(explainLineButton);
        buttonPanel.add(clearExplainButton);

        add(buttonPanel, BorderLayout.SOUTH);
    }

    private void setupListeners() {
        explainFunctionButton.addActionListener(e -> controller.handleExplainFunction());
        explainLineButton.addActionListener(e -> controller.handleExplainLine());
        clearExplainButton.addActionListener(e -> {
            // Clear the UI
            explainTextPane.setText("");
            markdownTextArea.setText("");
            currentMarkdown = "";
            
            // Also clear from database
            controller.handleClearAnalysisData();
        });
        
        editSaveButton.addActionListener(e -> {
            if (isEditMode) {
                // Save mode - save the markdown and switch to view mode
                currentMarkdown = markdownTextArea.getText();
                String html = markdownHelper.markdownToHtml(currentMarkdown);
                explainTextPane.setText(html);
                
                // Save to database
                controller.handleUpdateAnalysis(currentMarkdown);
                
                // Switch to view mode
                contentLayout.show(contentPanel, "view");
                editSaveButton.setText("Edit");
                isEditMode = false;
            } else {
                // Edit mode - switch to the markdown editor
                markdownTextArea.setText(currentMarkdown);
                
                // Switch to edit mode
                contentLayout.show(contentPanel, "edit");
                editSaveButton.setText("Save");
                isEditMode = true;
            }
        });

        // ESC key discards edits and returns to view mode
        markdownTextArea.getInputMap(JComponent.WHEN_FOCUSED)
            .put(KeyStroke.getKeyStroke("ESCAPE"), "cancelEdit");
        markdownTextArea.getActionMap().put("cancelEdit", new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent ae) {
                if (isEditMode) {
                    contentLayout.show(contentPanel, "view");
                    editSaveButton.setText("Edit");
                    isEditMode = false;
                }
            }
        });
    }

    public void updateOffset(String offset) {
        offsetField.setText(offset);
    }

    public void setExplanationText(String text) {
        explainTextPane.setText(text);
        explainTextPane.setCaretPosition(0);
        
        // Store the markdown equivalent
        currentMarkdown = markdownHelper.extractMarkdownFromLlmResponse(text);
        
        // If we're in edit mode, update the markdown text area too
        if (isEditMode) {
            markdownTextArea.setText(currentMarkdown);
        }
        
        // Switch to view mode if we're setting new content
        if (isEditMode) {
            contentLayout.show(contentPanel, "view");
            editSaveButton.setText("Edit");
            isEditMode = false;
        }
    }

    public void setFunctionButtonText(String text) {
        explainFunctionButton.setText(text);
    }

    public void setLineButtonText(String text) {
        explainLineButton.setText(text);
    }

    /**
     * Setup context menu for clipboard operations
     */
    private void setupContextMenu() {
        JPopupMenu contextMenu = new JPopupMenu();

        JMenuItem copyMarkdown = new JMenuItem("Copy as Markdown");
        copyMarkdown.addActionListener(e -> {
            String selectedText = isEditMode ?
                    markdownTextArea.getSelectedText() :
                    getSelectedMarkdownText();
            if (selectedText != null && !selectedText.isEmpty()) {
                copyToClipboard(selectedText);
            }
        });

        JMenuItem copyHtml = new JMenuItem("Copy as HTML");
        copyHtml.addActionListener(e -> {
            if (isEditMode) {
                String selectedText = markdownTextArea.getSelectedText();
                if (selectedText != null && !selectedText.isEmpty()) {
                    copyToClipboard(selectedText);
                }
            } else {
                int start = explainTextPane.getSelectionStart();
                int end = explainTextPane.getSelectionEnd();
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
                    markdownTextArea.getSelectedText() :
                    explainTextPane.getSelectedText();
            if (selectedText != null && !selectedText.isEmpty()) {
                copyToClipboard(selectedText);
            }
        });

        JMenuItem copyAll = new JMenuItem("Copy All as Markdown");
        copyAll.addActionListener(e -> {
            copyToClipboard(currentMarkdown);
        });

        JMenuItem selectAll = new JMenuItem("Select All");
        selectAll.addActionListener(e -> {
            if (isEditMode) {
                markdownTextArea.selectAll();
            } else {
                explainTextPane.selectAll();
            }
        });

        JMenuItem paste = new JMenuItem("Paste");
        paste.addActionListener(e -> {
            if (isEditMode) {
                markdownTextArea.paste();
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

        explainTextPane.setComponentPopupMenu(contextMenu);
        markdownTextArea.setComponentPopupMenu(contextMenu);

        // Override CTRL-C to copy markdown from view mode
        explainTextPane.getActionMap().put("copy", new AbstractAction() {
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
        String selectedText = explainTextPane.getSelectedText();
        if (selectedText == null || selectedText.isEmpty()) {
            return null;
        }
        if (currentMarkdown == null || currentMarkdown.isEmpty()) {
            return selectedText;
        }
        return mapRenderedTextToMarkdown(selectedText, currentMarkdown);
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
     * Extract HTML content for the selected range from the JEditorPane's HTMLDocument.
     */
    private String extractSelectedHtml(int start, int end) {
        try {
            HTMLEditorKit kit = (HTMLEditorKit) explainTextPane.getEditorKit();
            HTMLDocument doc = (HTMLDocument) explainTextPane.getDocument();
            StringWriter writer = new StringWriter();
            kit.write(writer, doc, start, end - start);
            return writer.toString();
        } catch (Exception e) {
            Msg.warn(this, "Failed to extract HTML: " + e.getMessage());
            // Fallback to plain text
            return explainTextPane.getSelectedText();
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

    /**
     * Get the current markdown content
     */
    public String getCurrentMarkdown() {
        return currentMarkdown;
    }

    /**
     * Set the markdown source directly (avoids lossy HTML-to-markdown conversion).
     *
     * @param markdown The original markdown content
     */
    public void setMarkdownSource(String markdown) {
        this.currentMarkdown = markdown != null ? markdown : "";
    }

    /**
     * Update the security info panel with analysis results.
     *
     * @param riskLevel Risk level (LOW, MEDIUM, HIGH) or null
     * @param category Category string or null
     * @param activityProfile Activity profile string or null
     * @param securityFlags List of security flags or null
     * @param networkAPIs List of network API calls or null
     * @param fileIOAPIs List of file I/O API calls or null
     */
    public void updateSecurityInfo(String riskLevel, String category, String activityProfile,
                                   List<String> securityFlags,
                                   List<String> networkAPIs, List<String> fileIOAPIs) {
        // Update risk level with color coding
        if (riskLevel != null && !riskLevel.isEmpty()) {
            riskLevelLabel.setText("Risk: " + riskLevel);
            switch (riskLevel.toUpperCase()) {
                case "HIGH":
                    riskLevelLabel.setForeground(new Color(180, 0, 0)); // Red
                    break;
                case "MEDIUM":
                    riskLevelLabel.setForeground(new Color(180, 120, 0)); // Orange
                    break;
                case "LOW":
                    riskLevelLabel.setForeground(new Color(0, 120, 0)); // Green
                    break;
                default:
                    riskLevelLabel.setForeground(UIManager.getColor("Label.foreground"));
            }
        } else {
            riskLevelLabel.setText("Risk: —");
            riskLevelLabel.setForeground(UIManager.getColor("Label.foreground"));
        }

        if (category != null && !category.isEmpty()) {
            categoryLabel.setText("Category: " + category);
        } else {
            categoryLabel.setText("Category: —");
        }

        // Update activity profile
        if (activityProfile != null && !activityProfile.isEmpty()) {
            activityProfileLabel.setText("Activity: " + activityProfile);
        } else {
            activityProfileLabel.setText("Activity: —");
        }

        // Update security flags
        if (securityFlags != null && !securityFlags.isEmpty()) {
            securityFlagsLabel.setText("<html>Flags: " + String.join(", ", securityFlags) + "</html>");
        } else {
            securityFlagsLabel.setText("<html>Flags: None</html>");
        }

        // Update network APIs
        if (networkAPIs != null && !networkAPIs.isEmpty()) {
            networkAPIsTextArea.setText(String.join("\n", networkAPIs));
        } else {
            networkAPIsTextArea.setText("(none detected)");
        }

        // Update file I/O APIs
        if (fileIOAPIs != null && !fileIOAPIs.isEmpty()) {
            fileIOAPIsTextArea.setText(String.join("\n", fileIOAPIs));
        } else {
            fileIOAPIsTextArea.setText("(none detected)");
        }

        // Show the panel if we have any data
        boolean hasData = (riskLevel != null && !riskLevel.isEmpty()) ||
                         (category != null && !category.isEmpty()) ||
                         (activityProfile != null && !activityProfile.isEmpty()) ||
                         (securityFlags != null && !securityFlags.isEmpty()) ||
                         (networkAPIs != null && !networkAPIs.isEmpty()) ||
                         (fileIOAPIs != null && !fileIOAPIs.isEmpty());
        securityInfoPanel.setVisible(hasData);

        // Set a reasonable initial divider location if the panel just appeared
        if (hasData && outerSplitPane != null) {
            SwingUtilities.invokeLater(() -> {
                int totalHeight = outerSplitPane.getHeight();
                if (totalHeight > 0 && outerSplitPane.getDividerLocation() >= totalHeight - 20) {
                    outerSplitPane.setDividerLocation(totalHeight - 160);
                }
            });
        }
    }

    /**
     * Clear the security info panel.
     */
    public void clearSecurityInfo() {
        riskLevelLabel.setText("Risk: —");
        riskLevelLabel.setForeground(UIManager.getColor("Label.foreground"));
        categoryLabel.setText("Category: —");
        activityProfileLabel.setText("Activity: —");
        securityFlagsLabel.setText("<html>Flags: None</html>");
        networkAPIsTextArea.setText("");
        fileIOAPIsTextArea.setText("");
        securityInfoPanel.setVisible(false);
    }

    /**
     * Set the line explanation text and make panel visible.
     *
     * @param text The explanation text (can be HTML or plain text)
     */
    public void setLineExplanationText(String text) {
        if (text == null || text.trim().isEmpty()) {
            clearLineExplanation();
            return;
        }

        lineExplanationMarkdown = text;
        lineExplanationTextPane.setText(text);
        lineExplanationTextPane.setCaretPosition(0);

        // Show the line explanation panel in the split pane
        if (mainSplitPane.getBottomComponent() == null) {
            lineExplanationPanel.setVisible(true);
            mainSplitPane.setBottomComponent(lineExplanationPanel);
            mainSplitPane.setDividerSize(8);

            // Set initial divider location to show ~180px for line explanation
            SwingUtilities.invokeLater(() -> {
                int totalHeight = mainSplitPane.getHeight();
                if (totalHeight > 250) {
                    mainSplitPane.setDividerLocation(totalHeight - 180);
                } else {
                    mainSplitPane.setDividerLocation(0.7);
                }
            });
        }

        // Revalidate layout
        revalidate();
        repaint();
    }

    /**
     * Clear the line explanation panel and hide it.
     */
    public void clearLineExplanation() {
        lineExplanationMarkdown = "";
        lineExplanationTextPane.setText("");

        // Hide the line explanation panel by removing from split pane
        mainSplitPane.setBottomComponent(null);
        mainSplitPane.setDividerSize(0);
        lineExplanationPanel.setVisible(false);

        // Revalidate layout
        revalidate();
        repaint();
    }

    /**
     * Set the Explain Line button enabled state.
     *
     * @param enabled true to enable, false to disable
     */
    public void setLineButtonEnabled(boolean enabled) {
        explainLineButton.setEnabled(enabled);
    }

    /**
     * Get the current line explanation markdown.
     *
     * @return The markdown text
     */
    public String getLineExplanationMarkdown() {
        return lineExplanationMarkdown;
    }

    /**
     * Check if the line explanation panel is currently visible.
     *
     * @return true if visible
     */
    public boolean isLineExplanationVisible() {
        return lineExplanationPanel.isVisible();
    }

    // ========================================
    // Streaming Methods for Function Explanation Pane
    // ========================================

    /**
     * Initialize the function explanation pane for streaming with a two-div DOM structure.
     *
     * @param prefixHtml Pre-rendered HTML for any prefix content (may be empty)
     */
    public void initializeForStreaming(String prefixHtml) {
        SwingUtilities.invokeLater(() -> {
            // Reset streaming state
            accumulatedCommittedHtml.setLength(0);
            lastPendingHtml = "<span></span>";
            documentCorrupted = false;

            // Switch to HTML mode
            explainTextPane.setContentType("text/html");
            HTMLEditorKit kit = new HTMLEditorKit();
            explainTextPane.setEditorKit(kit);

            // Build initial HTML with two-div structure
            String prefix = (prefixHtml != null && !prefixHtml.isEmpty()) ? prefixHtml : "";
            String initialHtml = String.format(
                "<html><head><style>%s</style></head><body>%s" +
                "<div id=\"committed\"></div>" +
                "<div id=\"pending\"><span></span></div>" +
                "</body></html>",
                getStreamingCSS(), prefix);

            explainTextPane.setText(initialHtml);

            // Switch to view mode if in edit mode
            if (isEditMode) {
                contentLayout.show(contentPanel, "view");
                editSaveButton.setText("Edit");
                isEditMode = false;
            }
        });
    }

    /**
     * Apply a render update to the function explanation streaming display.
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

        HTMLDocument doc = (HTMLDocument) explainTextPane.getDocument();

        try {
            // Append committed HTML
            if (committedHtml != null && !committedHtml.isEmpty()) {
                Element committedDiv = findElement(doc, "committed");
                if (committedDiv != null) {
                    doc.insertBeforeEnd(committedDiv, committedHtml);
                }
            }

            // Replace pending div atomically using setOuterHTML
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
                    fullHtml + "</body></html>";
            explainTextPane.setText(wrapped);
            documentCorrupted = false;

            // Store the markdown equivalent for edit mode
            currentMarkdown = markdownHelper.extractMarkdownFromLlmResponse(fullHtml);
        }
    }

    private void rebuildDocument() {
        String html = "<html><head><style>" + getStreamingCSS() + "</style></head><body>" +
                accumulatedCommittedHtml.toString() +
                lastPendingHtml +
                "</body></html>";
        explainTextPane.setText(html);
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

    // ========================================
    // Streaming Methods for Line Explanation Pane
    // ========================================

    /**
     * Initialize the line explanation pane for streaming with a two-div DOM structure.
     */
    public void initializeLineExplanationForStreaming() {
        SwingUtilities.invokeLater(() -> {
            // Reset streaming state
            lineAccumulatedCommittedHtml.setLength(0);
            lineLastPendingHtml = "<span></span>";
            lineDocumentCorrupted = false;

            // Switch to HTML mode
            lineExplanationTextPane.setContentType("text/html");
            HTMLEditorKit kit = new HTMLEditorKit();
            lineExplanationTextPane.setEditorKit(kit);

            // Build initial HTML with two-div structure
            String initialHtml = String.format(
                "<html><head><style>%s</style></head><body>" +
                "<div id=\"line-committed\"></div>" +
                "<div id=\"line-pending\"><span></span></div>" +
                "</body></html>",
                getStreamingCSS());

            lineExplanationTextPane.setText(initialHtml);

            // Ensure the line explanation panel is visible
            if (mainSplitPane.getBottomComponent() == null) {
                lineExplanationPanel.setVisible(true);
                mainSplitPane.setBottomComponent(lineExplanationPanel);
                mainSplitPane.setDividerSize(8);

                // Set initial divider location
                SwingUtilities.invokeLater(() -> {
                    int totalHeight = mainSplitPane.getHeight();
                    if (totalHeight > 250) {
                        mainSplitPane.setDividerLocation(totalHeight - 180);
                    } else {
                        mainSplitPane.setDividerLocation(0.7);
                    }
                });
            }

            revalidate();
            repaint();
        });
    }

    /**
     * Apply a render update to the line explanation streaming display.
     * Note: This method is called from EDT (via StreamingMarkdownRenderer's invokeLater).
     *
     * @param update The render update to apply
     */
    public void applyLineRenderUpdate(RenderUpdate update) {
        if (update == null) {
            return;
        }

        // Capture scroll state BEFORE any DOM modification
        boolean wasAtBottom = lineScrollManager.isAtBottom();
        int savedScrollValue = lineScrollManager.getScrollPane().getVerticalScrollBar().getValue();

        // Apply the update
        switch (update.getType()) {
            case INCREMENTAL -> applyLineIncrementalUpdate(update);
            case FULL_REPLACE -> applyLineFullReplaceUpdate(update);
        }

        // Restore scroll position or auto-scroll (matching reference implementation)
        if (wasAtBottom) {
            SwingUtilities.invokeLater(() -> lineScrollManager.scrollToBottom());
        } else {
            // Restore the user's scroll position exactly
            SwingUtilities.invokeLater(() ->
                    lineScrollManager.getScrollPane().getVerticalScrollBar().setValue(savedScrollValue));
        }
    }

    private void applyLineIncrementalUpdate(RenderUpdate update) {
        // Track content for fallback rebuilds
        String committedHtml = update.getCommittedHtmlToAppend();
        if (committedHtml != null && !committedHtml.isEmpty()) {
            lineAccumulatedCommittedHtml.append(committedHtml);
        }
        String pendingHtml = update.getPendingHtml();
        if (pendingHtml != null) {
            lineLastPendingHtml = pendingHtml;
        }

        // If document was previously corrupted, use full rebuild strategy
        if (lineDocumentCorrupted) {
            rebuildLineDocument();
            return;
        }

        HTMLDocument doc = (HTMLDocument) lineExplanationTextPane.getDocument();

        try {
            // Append committed HTML
            if (committedHtml != null && !committedHtml.isEmpty()) {
                Element committedDiv = findElement(doc, "line-committed");
                if (committedDiv != null) {
                    doc.insertBeforeEnd(committedDiv, committedHtml);
                }
            }

            // Replace pending div atomically using setOuterHTML
            if (pendingHtml != null) {
                Element pendingDiv = findElement(doc, "line-pending");
                if (pendingDiv != null) {
                    String wrappedPending = "<div id=\"line-pending\">" + pendingHtml + "</div>";
                    doc.setOuterHTML(pendingDiv, wrappedPending);
                }
            }
        } catch (Exception e) {
            Msg.warn(this, "Line DOM update failed, switching to rebuild strategy: " + e.getMessage());
            lineDocumentCorrupted = true;
            rebuildLineDocument();
        }
    }

    private void applyLineFullReplaceUpdate(RenderUpdate update) {
        String fullHtml = update.getFullHtml();
        if (fullHtml != null) {
            String wrapped = "<html><head><style>" + getStreamingCSS() + "</style></head><body>" +
                    fullHtml + "</body></html>";
            lineExplanationTextPane.setText(wrapped);
            lineDocumentCorrupted = false;

            // Store the markdown equivalent
            lineExplanationMarkdown = markdownHelper.extractMarkdownFromLlmResponse(fullHtml);
        }
    }

    private void rebuildLineDocument() {
        String html = "<html><head><style>" + getStreamingCSS() + "</style></head><body>" +
                lineAccumulatedCommittedHtml.toString() +
                lineLastPendingHtml +
                "</body></html>";
        lineExplanationTextPane.setText(html);
    }
}
