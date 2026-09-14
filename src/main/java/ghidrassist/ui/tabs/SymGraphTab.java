package ghidrassist.ui.tabs;

import ghidrassist.core.TabController;
import ghidra.framework.preferences.Preferences;
import ghidrassist.services.symgraph.SymGraphModels.BinaryRevision;
import ghidrassist.services.symgraph.SymGraphModels.ConflictAction;
import ghidrassist.services.symgraph.SymGraphModels.ConflictEntry;
import ghidrassist.services.symgraph.SymGraphModels.DocumentSummary;
import ghidrassist.services.symgraph.SymGraphModels.GraphExport;
import ghidrassist.services.symgraph.SymGraphModels.PushScope;

import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.net.URI;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * SymGraph tab with overview, import, and publish workflows.
 */
public class SymGraphTab extends JPanel {
    private static final long serialVersionUID = 1L;

    private static final String MERGE_POLICY_UPSERT = "upsert";
    private static final String MERGE_POLICY_PREFER_LOCAL = "prefer_local";
    private static final String MERGE_POLICY_REPLACE = "replace";
    private final TabController controller;

    // Shared binary info
    private JLabel binaryNameLabel;
    private JLabel sha256Label;
    private JLabel localSummaryLabel;

    // Overview
    private JCheckBox autoRefreshCheckBox;
    private JButton queryButton;
    private JButton uploadBinaryButton;
    private JButton openBinaryButton;
    private JLabel statusLabel;
    private JLabel statusBadgeLabel;
    private JLabel storageStatusLabel;
    private JPanel statsPanel;
    private JLabel symbolsStatLabel;
    private JLabel functionsStatLabel;
    private JLabel nodesStatLabel;
    private JLabel edgesStatLabel;
    private JLabel updatedStatLabel;
    private JLabel latestRevisionLabel;
    private JLabel accessibleVersionsLabel;
    private String openBinaryUrl;
    private JTabbedPane workflowTabs;

    // Fetch tab
    private JComboBox<String> fetchVersionCombo;
    private JTextField fetchNameFilterField;
    private JCheckBox pullFunctionsCheck;
    private JCheckBox pullVariablesCheck;
    private JCheckBox pullTypesCheck;
    private JCheckBox pullCommentsCheck;
    private JCheckBox pullGraphCheck;
    private JSlider confidenceSlider;
    private JLabel confidenceValueLabel;
    private JButton pullPreviewButton;
    private JButton fetchResetButton;
    private JToggleButton fetchAdvancedToggle;
    private JPanel fetchAdvancedPanel;
    private JLabel summaryNewCountLabel;
    private JLabel summaryConflictCountLabel;
    private JLabel summarySameCountLabel;
    private JLabel summarySelectedCountLabel;
    private JLabel summaryDocumentCountLabel;
    private JLabel summaryGraphNodesLabel;
    private JLabel summaryGraphEdgesLabel;
    private JLabel summaryGraphVersionLabel;
    private JCheckBox filterNewCheck;
    private JCheckBox filterConflictsCheck;
    private JCheckBox filterSameCheck;
    private JTable conflictTable;
    private DefaultTableModel conflictTableModel;
    private JTable fetchDocumentsTable;
    private DefaultTableModel fetchDocumentsTableModel;
    private JLabel fetchGraphSummaryLabel;
    private JButton selectAllButton;
    private JButton deselectAllButton;
    private JButton selectNewButton;
    private JButton selectConflictsButton;
    private JButton invertSelectionButton;
    private JButton applyAllNewButton;
    private JButton applyButton;
    private JProgressBar fetchProgressBar;
    private JLabel fetchProgressLabel;
    private JLabel pullStatusLabel;

    // Push tab
    private JRadioButton fullBinaryRadio;
    private JRadioButton currentFunctionRadio;
    private JComboBox<String> pushVisibilityCombo;
    private JCheckBox pushFunctionsCheck;
    private JCheckBox pushVariablesCheck;
    private JCheckBox pushTypesCheck;
    private JCheckBox pushCommentsCheck;
    private JCheckBox pushGraphCheck;
    private JTextField pushNameFilterField;
    private JButton pushPreviewButton;
    private JButton pushResetButton;
    private JToggleButton pushAdvancedToggle;
    private JPanel pushAdvancedPanel;
    private JButton pushButton;
    private JLabel pushMatchingCountLabel;
    private JLabel pushSelectedCountLabel;
    private JLabel pushDocumentsCountLabel;
    private JLabel pushGraphNodesLabel;
    private JLabel pushGraphEdgesLabel;
    private JTable pushPreviewTable;
    private DefaultTableModel pushPreviewTableModel;
    private JTable pushDocumentsTable;
    private DefaultTableModel pushDocumentsTableModel;
    private JLabel pushGraphSummaryLabel;
    private JButton pushSelectAllButton;
    private JButton pushDeselectAllButton;
    private JButton pushInvertSelectionButton;
    private JProgressBar pushProgressBar;
    private JLabel pushProgressLabel;
    private JLabel pushStatusLabel;
    private Runnable pushCancelCallback;

    // State
    private final List<ConflictEntry> allConflicts = new ArrayList<>();
    private final List<ConflictEntry> displayedConflicts = new ArrayList<>();
    private final Map<String, Boolean> conflictSelectionState = new HashMap<>();
    private final List<DocumentSummary> displayedFetchDocuments = new ArrayList<>();
    private final List<Map<String, Object>> pushPreviewSymbols = new ArrayList<>();
    private final List<Map<String, Object>> pushPreviewDocuments = new ArrayList<>();
    private GraphExport graphPreviewData;
    private int graphPreviewNodes;
    private int graphPreviewEdges;
    private String graphMergePolicy = MERGE_POLICY_UPSERT;
    private Map<String, Object> pushGraphData;
    private int pushGraphNodes;
    private int pushGraphEdges;

    public SymGraphTab(TabController controller) {
        super(new BorderLayout());
        this.controller = controller;
        initializeComponents();
        layoutComponents();
        setupListeners();
    }

    private void initializeComponents() {
        binaryNameLabel = new JLabel("<no binary loaded>");
        binaryNameLabel.setFont(binaryNameLabel.getFont().deriveFont(Font.BOLD));
        sha256Label = new JLabel("<none>");
        sha256Label.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 11));
        localSummaryLabel = new JLabel("No binary loaded");
        localSummaryLabel.setForeground(Color.GRAY);

        autoRefreshCheckBox = new JCheckBox("Auto-refresh");
        autoRefreshCheckBox.setSelected(Boolean.parseBoolean(
                Preferences.getProperty("GhidrAssist.SymGraphAutoRefresh", "false")));
        queryButton = new JButton("Refresh");
        uploadBinaryButton = new JButton("Upload Binary");
        openBinaryButton = new JButton("Open in SymGraph");
        openBinaryButton.setEnabled(false);
        statusLabel = new JLabel("Not checked");
        statusLabel.setForeground(Color.GRAY);
        statusBadgeLabel = new JLabel("Not checked");
        statusBadgeLabel.setOpaque(true);
        statusBadgeLabel.setBorder(BorderFactory.createEmptyBorder(2, 8, 2, 8));
        statusBadgeLabel.setBackground(UIManager.getColor("Panel.background"));
        storageStatusLabel = new JLabel("Stored Binary: Unknown");
        storageStatusLabel.setForeground(Color.GRAY);
        symbolsStatLabel = new JLabel("Symbols: -");
        functionsStatLabel = new JLabel("Functions: -");
        nodesStatLabel = new JLabel("Graph Nodes: -");
        edgesStatLabel = new JLabel("Graph Edges: -");
        updatedStatLabel = new JLabel("Last Updated: -");
        latestRevisionLabel = new JLabel("Latest Version: -");
        accessibleVersionsLabel = new JLabel("Accessible Versions: -");
        statsPanel = new JPanel(new GridBagLayout());
        GridBagConstraints statsGbc = new GridBagConstraints();
        statsGbc.anchor = GridBagConstraints.WEST;
        statsGbc.insets = new Insets(2, 5, 2, 24);
        statsGbc.gridx = 0;
        statsGbc.gridy = 0;
        statsPanel.add(symbolsStatLabel, statsGbc);
        statsGbc.gridx = 1;
        statsPanel.add(functionsStatLabel, statsGbc);
        statsGbc.gridx = 0;
        statsGbc.gridy = 1;
        statsPanel.add(nodesStatLabel, statsGbc);
        statsGbc.gridx = 1;
        statsPanel.add(edgesStatLabel, statsGbc);
        statsGbc.gridx = 0;
        statsGbc.gridy = 2;
        statsPanel.add(updatedStatLabel, statsGbc);
        statsGbc.gridx = 1;
        statsPanel.add(latestRevisionLabel, statsGbc);
        statsGbc.gridx = 0;
        statsGbc.gridy = 3;
        statsPanel.add(accessibleVersionsLabel, statsGbc);
        statsGbc.gridx = 1;
        statsPanel.add(storageStatusLabel, statsGbc);
        statsPanel.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createEtchedBorder(),
                BorderFactory.createEmptyBorder(6, 8, 6, 8)));
        statsPanel.setVisible(false);

        fetchVersionCombo = new JComboBox<>();
        fetchVersionCombo.addItem("Latest");
        fetchNameFilterField = new JTextField(18);
        pullFunctionsCheck = new JCheckBox("Functions", true);
        pullVariablesCheck = new JCheckBox("Variables", true);
        pullTypesCheck = new JCheckBox("Types", true);
        pullCommentsCheck = new JCheckBox("Comments", true);
        pullGraphCheck = new JCheckBox("Include Graph Data", true);
        confidenceSlider = new JSlider(JSlider.HORIZONTAL, 0, 100, 0);
        confidenceValueLabel = new JLabel("0.0");
        pullPreviewButton = new JButton("Preview Import");
        fetchResetButton = new JButton("Reset");
        fetchAdvancedToggle = createDisclosureToggle("Advanced Filters");
        fetchAdvancedPanel = new JPanel(new GridBagLayout());
        summaryNewCountLabel = new JLabel("New: 0");
        summaryConflictCountLabel = new JLabel("Conflicts: 0");
        summarySameCountLabel = new JLabel("Same: 0");
        summarySelectedCountLabel = new JLabel("Selected: 0 symbols / 0 docs");
        summaryDocumentCountLabel = new JLabel("Documents: 0");
        summaryGraphNodesLabel = new JLabel("Graph Nodes: 0");
        summaryGraphEdgesLabel = new JLabel("Graph Edges: 0");
        summaryGraphVersionLabel = new JLabel("Version: -");
        filterNewCheck = new JCheckBox("New", true);
        filterConflictsCheck = new JCheckBox("Conflicts", true);
        filterSameCheck = new JCheckBox("Unchanged", false);
        fetchProgressBar = new JProgressBar(0, 100);
        fetchProgressBar.setVisible(false);
        fetchProgressLabel = new JLabel("");
        fetchProgressLabel.setForeground(Color.GRAY);
        fetchProgressLabel.setVisible(false);
        pullStatusLabel = new JLabel("");
        pullStatusLabel.setForeground(Color.GRAY);

        conflictTableModel = new DefaultTableModel(
                new Object[]{"Select", "Address", "Type/Storage", "Local Name", "Remote Name", "Status"}, 0) {
            private static final long serialVersionUID = 1L;
            @Override
            public Class<?> getColumnClass(int columnIndex) {
                return columnIndex == 0 ? Boolean.class : String.class;
            }
            @Override
            public boolean isCellEditable(int row, int column) {
                return column == 0;
            }
        };
        conflictTable = new JTable(conflictTableModel);
        fetchDocumentsTableModel = new DefaultTableModel(
                new Object[]{"Select", "Title", "Size", "Date", "Version"}, 0) {
            private static final long serialVersionUID = 1L;
            @Override
            public Class<?> getColumnClass(int columnIndex) {
                return columnIndex == 0 ? Boolean.class : String.class;
            }
            @Override
            public boolean isCellEditable(int row, int column) {
                return column == 0;
            }
        };
        fetchDocumentsTable = new JTable(fetchDocumentsTableModel);
        fetchGraphSummaryLabel = new JLabel("No graph data loaded.");
        selectAllButton = new JButton("Select All");
        deselectAllButton = new JButton("Deselect All");
        selectNewButton = new JButton("Select New");
        selectConflictsButton = new JButton("Select Conflicts");
        invertSelectionButton = new JButton("Invert");
        applyAllNewButton = new JButton("Apply Recommended");
        applyButton = new JButton("Apply Selected");

        fullBinaryRadio = new JRadioButton("Full Binary");
        currentFunctionRadio = new JRadioButton("Current Function", true);
        ButtonGroup scopeGroup = new ButtonGroup();
        scopeGroup.add(fullBinaryRadio);
        scopeGroup.add(currentFunctionRadio);
        pushVisibilityCombo = new JComboBox<>(new String[]{"Public", "Private"});
        pushFunctionsCheck = new JCheckBox("Functions", true);
        pushVariablesCheck = new JCheckBox("Variables", true);
        pushTypesCheck = new JCheckBox("Types", true);
        pushCommentsCheck = new JCheckBox("Comments", false);
        pushGraphCheck = new JCheckBox("Include Graph Data", true);
        pushNameFilterField = new JTextField(18);
        pushPreviewButton = new JButton("Preview Publish");
        pushResetButton = new JButton("Reset");
        pushAdvancedToggle = createDisclosureToggle("Advanced Filters");
        pushAdvancedPanel = new JPanel(new GridBagLayout());
        pushButton = new JButton("Publish Selected");
        pushMatchingCountLabel = new JLabel("Matching: 0");
        pushSelectedCountLabel = new JLabel("Selected: 0 symbols / 0 docs");
        pushDocumentsCountLabel = new JLabel("Documents: 0");
        pushGraphNodesLabel = new JLabel("Graph Nodes: 0");
        pushGraphEdgesLabel = new JLabel("Graph Edges: 0");
        pushGraphSummaryLabel = new JLabel("No graph data included in this publish preview.");
        pushProgressBar = new JProgressBar(0, 100);
        pushProgressBar.setVisible(false);
        pushProgressLabel = new JLabel("");
        pushProgressLabel.setForeground(Color.GRAY);
        pushProgressLabel.setVisible(false);
        pushStatusLabel = new JLabel("Status: Ready");
        pushStatusLabel.setForeground(Color.GRAY);

        pushPreviewTableModel = new DefaultTableModel(
                new Object[]{"Select", "Address", "Type", "Name", "Confidence", "Provenance"}, 0) {
            private static final long serialVersionUID = 1L;
            @Override
            public Class<?> getColumnClass(int columnIndex) {
                return columnIndex == 0 ? Boolean.class : String.class;
            }
            @Override
            public boolean isCellEditable(int row, int column) {
                return column == 0;
            }
        };
        pushPreviewTable = new JTable(pushPreviewTableModel);
        pushDocumentsTableModel = new DefaultTableModel(
                new Object[]{"Select", "Title", "Size", "Date", "Version", "Doc Type"}, 0) {
            private static final long serialVersionUID = 1L;
            @Override
            public Class<?> getColumnClass(int columnIndex) {
                return columnIndex == 0 ? Boolean.class : String.class;
            }
            @Override
            public boolean isCellEditable(int row, int column) {
                return column == 0 || column == 5;
            }
        };
        pushDocumentsTable = new JTable(pushDocumentsTableModel);
        JComboBox<String> docTypeCombo = new JComboBox<>(new String[]{
                "General", "Malware Report", "Vulnerability Analysis", "API Documentation", "Notes"
        });
        pushDocumentsTable.getColumnModel().getColumn(5).setCellEditor(new DefaultCellEditor(docTypeCombo));
        pushSelectAllButton = new JButton("Select All");
        pushDeselectAllButton = new JButton("Deselect All");
        pushInvertSelectionButton = new JButton("Invert");
    }

    private void layoutComponents() {
        JPanel mainPanel = new JPanel(new BorderLayout(5, 5));
        mainPanel.setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5));
        mainPanel.add(createOverviewPanel(), BorderLayout.NORTH);

        workflowTabs = new JTabbedPane();
        workflowTabs.addTab("Import From SymGraph", createFetchTab());
        workflowTabs.addTab("Publish To SymGraph", createPushTab());
        mainPanel.add(workflowTabs, BorderLayout.CENTER);

        add(mainPanel, BorderLayout.CENTER);
    }

    private JPanel createOverviewPanel() {
        JPanel panel = new JPanel(new GridBagLayout());
        GridBagConstraints panelGbc = new GridBagConstraints();
        panelGbc.gridx = 0;
        panelGbc.weightx = 1.0;
        panelGbc.fill = GridBagConstraints.HORIZONTAL;
        panelGbc.anchor = GridBagConstraints.NORTHWEST;

        JPanel binaryPanel = new JPanel(new GridBagLayout());
        binaryPanel.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createTitledBorder("Local Status"),
                BorderFactory.createEmptyBorder(5, 5, 5, 5)));

        GridBagConstraints gbc = new GridBagConstraints();
        gbc.anchor = GridBagConstraints.WEST;
        gbc.insets = new Insets(2, 5, 2, 5);

        gbc.gridx = 0;
        gbc.gridy = 0;
        binaryPanel.add(new JLabel("Binary:"), gbc);
        gbc.gridx = 1;
        gbc.weightx = 1.0;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        binaryPanel.add(binaryNameLabel, gbc);

        gbc.gridx = 0;
        gbc.gridy = 1;
        gbc.weightx = 0;
        gbc.fill = GridBagConstraints.NONE;
        binaryPanel.add(new JLabel("SHA256:"), gbc);
        gbc.gridx = 1;
        gbc.weightx = 1.0;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        binaryPanel.add(sha256Label, gbc);

        gbc.gridx = 0;
        gbc.gridy = 2;
        gbc.weightx = 0;
        gbc.fill = GridBagConstraints.NONE;
        binaryPanel.add(new JLabel("Local Summary:"), gbc);
        gbc.gridx = 1;
        gbc.weightx = 1.0;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        binaryPanel.add(localSummaryLabel, gbc);

        JPanel statusCard = new JPanel();
        statusCard.setLayout(new BoxLayout(statusCard, BoxLayout.Y_AXIS));
        statusCard.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createTitledBorder("Remote Status"),
                BorderFactory.createEmptyBorder(5, 5, 5, 5)));

        JPanel buttonRow = new JPanel(new FlowLayout(FlowLayout.RIGHT, 5, 0));
        buttonRow.setAlignmentX(Component.LEFT_ALIGNMENT);
        buttonRow.add(autoRefreshCheckBox);
        buttonRow.add(queryButton);
        buttonRow.add(uploadBinaryButton);
        buttonRow.add(openBinaryButton);
        statusCard.add(buttonRow);

        JPanel statusRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 0));
        statusRow.setAlignmentX(Component.LEFT_ALIGNMENT);
        statusRow.add(statusBadgeLabel);
        statusRow.add(statusLabel);
        statusCard.add(statusRow);

        statsPanel.setAlignmentX(Component.LEFT_ALIGNMENT);
        statusCard.add(statsPanel);

        panelGbc.gridy = 0;
        panel.add(binaryPanel, panelGbc);

        panelGbc.gridy = 1;
        panelGbc.insets = new Insets(5, 0, 0, 0);
        panel.add(statusCard, panelGbc);

        return panel;
    }

    private JPanel createFetchTab() {
        JPanel panel = new JPanel(new BorderLayout(5, 5));

        JPanel config = new JPanel();
        config.setLayout(new BoxLayout(config, BoxLayout.Y_AXIS));
        config.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createTitledBorder("Import Configuration"),
                BorderFactory.createEmptyBorder(5, 5, 5, 5)));

        JPanel row1 = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 0));
        row1.add(new JLabel("Source Revision:"));
        row1.add(fetchVersionCombo);
        row1.add(Box.createHorizontalStrut(12));
        row1.add(fetchAdvancedToggle);
        config.add(row1);

        JPanel row2 = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 0));
        row2.add(new JLabel("Include:"));
        row2.add(pullFunctionsCheck);
        row2.add(pullVariablesCheck);
        row2.add(pullTypesCheck);
        row2.add(pullCommentsCheck);
        row2.add(pullGraphCheck);
        config.add(row2);

        configureFetchAdvancedPanel();
        fetchAdvancedPanel.setVisible(false);
        config.add(fetchAdvancedPanel);

        JPanel row3 = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 0));
        row3.add(pullPreviewButton);
        row3.add(fetchResetButton);
        config.add(row3);
        panel.add(config, BorderLayout.NORTH);

        JPanel center = new JPanel(new BorderLayout(5, 5));
        JPanel summary = new JPanel(new FlowLayout(FlowLayout.LEFT, 10, 0));
        summary.setBorder(BorderFactory.createEtchedBorder());
        summary.add(summaryNewCountLabel);
        summary.add(summaryConflictCountLabel);
        summary.add(summarySameCountLabel);
        summary.add(summarySelectedCountLabel);
        summary.add(summaryDocumentCountLabel);
        summary.add(summaryGraphNodesLabel);
        summary.add(summaryGraphEdgesLabel);
        summary.add(summaryGraphVersionLabel);
        center.add(summary, BorderLayout.NORTH);

        configureTable(conflictTable, 6, 110, 130, 90);
        configureDocumentTable(fetchDocumentsTable, false);

        JTabbedPane fetchPreviewTabs = new JTabbedPane();

        JPanel changesPanel = new JPanel(new BorderLayout(5, 5));
        JPanel filterRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 0));
        filterRow.add(new JLabel("Show:"));
        filterRow.add(filterNewCheck);
        filterRow.add(filterConflictsCheck);
        filterRow.add(filterSameCheck);
        changesPanel.add(filterRow, BorderLayout.NORTH);

        JScrollPane symbolsScroll = new JScrollPane(conflictTable);
        symbolsScroll.setPreferredSize(new Dimension(0, 280));
        changesPanel.add(symbolsScroll, BorderLayout.CENTER);

        JPanel selectionRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 0));
        selectionRow.add(selectAllButton);
        selectionRow.add(deselectAllButton);
        selectionRow.add(selectNewButton);
        selectionRow.add(selectConflictsButton);
        selectionRow.add(invertSelectionButton);

        JPanel actionRow = new JPanel(new FlowLayout(FlowLayout.RIGHT, 5, 0));
        actionRow.add(applyAllNewButton);
        actionRow.add(applyButton);

        JPanel footerRow = new JPanel(new BorderLayout(5, 0));
        footerRow.add(selectionRow, BorderLayout.WEST);
        footerRow.add(actionRow, BorderLayout.EAST);
        changesPanel.add(footerRow, BorderLayout.SOUTH);
        fetchPreviewTabs.addTab("Changes", changesPanel);

        JPanel documentsPanel = new JPanel(new BorderLayout(5, 5));
        JScrollPane documentsScroll = new JScrollPane(fetchDocumentsTable);
        documentsPanel.add(documentsScroll, BorderLayout.CENTER);
        fetchPreviewTabs.addTab("Documents", documentsPanel);

        JPanel graphPanel = new JPanel(new BorderLayout(5, 5));
        fetchGraphSummaryLabel.setVerticalAlignment(SwingConstants.TOP);
        graphPanel.add(fetchGraphSummaryLabel, BorderLayout.NORTH);
        fetchPreviewTabs.addTab("Graph", graphPanel);

        center.add(fetchPreviewTabs, BorderLayout.CENTER);

        JPanel bottom = new JPanel();
        bottom.setLayout(new BoxLayout(bottom, BoxLayout.Y_AXIS));
        bottom.add(fetchProgressBar);
        bottom.add(fetchProgressLabel);
        bottom.add(pullStatusLabel);
        center.add(bottom, BorderLayout.SOUTH);

        panel.add(center, BorderLayout.CENTER);
        return panel;
    }

    private JPanel createPushTab() {
        JPanel panel = new JPanel(new BorderLayout(5, 5));

        JPanel config = new JPanel();
        config.setLayout(new BoxLayout(config, BoxLayout.Y_AXIS));
        config.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createTitledBorder("Publish Configuration"),
                BorderFactory.createEmptyBorder(5, 5, 5, 5)));

        JPanel row1 = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 0));
        row1.add(new JLabel("Scope:"));
        row1.add(fullBinaryRadio);
        row1.add(currentFunctionRadio);
        row1.add(new JLabel("Visibility:"));
        row1.add(pushVisibilityCombo);
        row1.add(Box.createHorizontalStrut(12));
        row1.add(pushAdvancedToggle);
        config.add(row1);

        JPanel row2 = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 0));
        row2.add(new JLabel("Include:"));
        row2.add(pushFunctionsCheck);
        row2.add(pushVariablesCheck);
        row2.add(pushTypesCheck);
        row2.add(pushCommentsCheck);
        row2.add(pushGraphCheck);
        config.add(row2);

        configurePushAdvancedPanel();
        pushAdvancedPanel.setVisible(false);
        config.add(pushAdvancedPanel);

        JPanel row3 = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 0));
        row3.add(pushPreviewButton);
        row3.add(pushResetButton);
        config.add(row3);
        panel.add(config, BorderLayout.NORTH);

        JPanel center = new JPanel(new BorderLayout(5, 5));
        JPanel summary = new JPanel(new FlowLayout(FlowLayout.LEFT, 10, 0));
        summary.setBorder(BorderFactory.createEtchedBorder());
        summary.add(pushMatchingCountLabel);
        summary.add(pushSelectedCountLabel);
        summary.add(pushDocumentsCountLabel);
        summary.add(pushGraphNodesLabel);
        summary.add(pushGraphEdgesLabel);
        center.add(summary, BorderLayout.NORTH);

        configureTable(pushPreviewTable, 6, 110, 100, 90);
        configureDocumentTable(pushDocumentsTable, true);

        JTabbedPane pushPreviewTabs = new JTabbedPane();

        JPanel symbolsPanel = new JPanel(new BorderLayout(5, 5));
        JScrollPane symbolsScroll = new JScrollPane(pushPreviewTable);
        symbolsScroll.setPreferredSize(new Dimension(0, 280));
        symbolsPanel.add(symbolsScroll, BorderLayout.CENTER);

        JPanel selectionRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 0));
        selectionRow.add(pushSelectAllButton);
        selectionRow.add(pushDeselectAllButton);
        selectionRow.add(pushInvertSelectionButton);

        JPanel actionRow = new JPanel(new FlowLayout(FlowLayout.RIGHT, 5, 0));
        actionRow.add(pushButton);

        JPanel footerRow = new JPanel(new BorderLayout(5, 0));
        footerRow.add(selectionRow, BorderLayout.WEST);
        footerRow.add(actionRow, BorderLayout.EAST);
        symbolsPanel.add(footerRow, BorderLayout.SOUTH);
        pushPreviewTabs.addTab("Symbols", symbolsPanel);

        JPanel documentsPanel = new JPanel(new BorderLayout(5, 5));
        JScrollPane documentsScroll = new JScrollPane(pushDocumentsTable);
        documentsPanel.add(documentsScroll, BorderLayout.CENTER);
        pushPreviewTabs.addTab("Documents", documentsPanel);

        JPanel graphPanel = new JPanel(new BorderLayout(5, 5));
        pushGraphSummaryLabel.setVerticalAlignment(SwingConstants.TOP);
        graphPanel.add(pushGraphSummaryLabel, BorderLayout.NORTH);
        pushPreviewTabs.addTab("Graph", graphPanel);

        center.add(pushPreviewTabs, BorderLayout.CENTER);

        JPanel bottom = new JPanel();
        bottom.setLayout(new BoxLayout(bottom, BoxLayout.Y_AXIS));
        bottom.add(pushProgressBar);
        bottom.add(pushProgressLabel);
        bottom.add(pushStatusLabel);
        center.add(bottom, BorderLayout.SOUTH);

        panel.add(center, BorderLayout.CENTER);
        return panel;
    }

    private void configureTable(JTable table, int columns, int addressWidth, int typeWidth, int actionWidth) {
        table.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);
        table.setAutoResizeMode(JTable.AUTO_RESIZE_SUBSEQUENT_COLUMNS);
        table.setFillsViewportHeight(true);
        table.getColumnModel().getColumn(0).setMinWidth(50);
        table.getColumnModel().getColumn(0).setMaxWidth(60);
        table.getColumnModel().getColumn(1).setMinWidth(80);
        table.getColumnModel().getColumn(1).setPreferredWidth(addressWidth);
        table.getColumnModel().getColumn(2).setMinWidth(90);
        table.getColumnModel().getColumn(2).setPreferredWidth(typeWidth);
        table.getColumnModel().getColumn(columns - 1).setMinWidth(70);
        table.getColumnModel().getColumn(columns - 1).setPreferredWidth(actionWidth);
    }

    private void configureDocumentTable(JTable table, boolean editableDocType) {
        table.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);
        table.setAutoResizeMode(JTable.AUTO_RESIZE_SUBSEQUENT_COLUMNS);
        table.setFillsViewportHeight(true);
        table.getColumnModel().getColumn(0).setMinWidth(50);
        table.getColumnModel().getColumn(0).setMaxWidth(60);
        table.getColumnModel().getColumn(2).setMinWidth(70);
        table.getColumnModel().getColumn(2).setPreferredWidth(80);
        table.getColumnModel().getColumn(4).setMinWidth(60);
        table.getColumnModel().getColumn(4).setPreferredWidth(70);
        if (editableDocType) {
            table.getColumnModel().getColumn(5).setMinWidth(120);
            table.getColumnModel().getColumn(5).setPreferredWidth(140);
        }
    }

    private void configureFetchAdvancedPanel() {
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.anchor = GridBagConstraints.WEST;
        gbc.insets = new Insets(2, 0, 2, 12);

        gbc.gridx = 0;
        gbc.gridy = 0;
        fetchAdvancedPanel.add(new JLabel("Name Filter:"), gbc);
        gbc.gridx = 1;
        fetchAdvancedPanel.add(fetchNameFilterField, gbc);

        gbc.gridx = 0;
        gbc.gridy = 1;
        fetchAdvancedPanel.add(new JLabel("Min Confidence:"), gbc);
        gbc.gridx = 1;
        fetchAdvancedPanel.add(confidenceSlider, gbc);
        gbc.gridx = 2;
        gbc.insets = new Insets(2, 0, 2, 0);
        fetchAdvancedPanel.add(confidenceValueLabel, gbc);

        gbc.gridx = 0;
        gbc.gridy = 2;
        gbc.insets = new Insets(2, 0, 2, 12);
        fetchAdvancedPanel.add(new JLabel("Graph Merge:"), gbc);
        gbc.gridx = 1;
        gbc.gridwidth = 2;
        fetchAdvancedPanel.add(createMergePolicyPanel(), gbc);
    }

    private void configurePushAdvancedPanel() {
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.anchor = GridBagConstraints.WEST;
        gbc.insets = new Insets(2, 0, 2, 12);
        gbc.gridx = 0;
        gbc.gridy = 0;
        pushAdvancedPanel.add(new JLabel("Name Filter:"), gbc);
        gbc.gridx = 1;
        pushAdvancedPanel.add(pushNameFilterField, gbc);
    }

    private JToggleButton createDisclosureToggle(String label) {
        JToggleButton toggle = new JToggleButton(label);
        toggle.setFocusable(false);
        return toggle;
    }

    private JPanel createMergePolicyPanel() {
        JPanel panel = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 0));
        ButtonGroup group = new ButtonGroup();
        JRadioButton upsert = new JRadioButton("Upsert", true);
        upsert.setActionCommand(MERGE_POLICY_UPSERT);
        JRadioButton preferLocal = new JRadioButton("Prefer Local");
        preferLocal.setActionCommand(MERGE_POLICY_PREFER_LOCAL);
        JRadioButton replace = new JRadioButton("Replace");
        replace.setActionCommand(MERGE_POLICY_REPLACE);
        group.add(upsert);
        group.add(preferLocal);
        group.add(replace);
        upsert.addActionListener(e -> graphMergePolicy = e.getActionCommand());
        preferLocal.addActionListener(e -> graphMergePolicy = e.getActionCommand());
        replace.addActionListener(e -> graphMergePolicy = e.getActionCommand());
        panel.add(upsert);
        panel.add(preferLocal);
        panel.add(replace);
        return panel;
    }

    private void setupListeners() {
        autoRefreshCheckBox.addActionListener(e -> {
            Preferences.setProperty(
                    "GhidrAssist.SymGraphAutoRefresh",
                    Boolean.toString(autoRefreshCheckBox.isSelected()));
            Preferences.store();
        });
        queryButton.addActionListener(e -> controller.handleSymGraphQuery());
        uploadBinaryButton.addActionListener(e -> controller.handleSymGraphUpload());
        openBinaryButton.addActionListener(e -> {
            if (openBinaryUrl != null && Desktop.isDesktopSupported()) {
                try {
                    Desktop.getDesktop().browse(new URI(openBinaryUrl));
                } catch (Exception ignored) {
                }
            }
        });
        pullPreviewButton.addActionListener(e -> controller.handleSymGraphPullPreview());
        fetchResetButton.addActionListener(e -> clearConflicts());
        fetchAdvancedToggle.addActionListener(e -> {
            fetchAdvancedPanel.setVisible(fetchAdvancedToggle.isSelected());
            fetchAdvancedPanel.revalidate();
            fetchAdvancedPanel.repaint();
        });
        selectAllButton.addActionListener(e -> {
            setAllSelected(conflictTableModel, true);
            setAllSelected(fetchDocumentsTableModel, true);
        });
        deselectAllButton.addActionListener(e -> {
            setAllSelected(conflictTableModel, false);
            setAllSelected(fetchDocumentsTableModel, false);
        });
        selectNewButton.addActionListener(e -> selectFetchAction(ConflictAction.NEW));
        selectConflictsButton.addActionListener(e -> selectFetchAction(ConflictAction.CONFLICT));
        invertSelectionButton.addActionListener(e -> {
            invertSelection(conflictTableModel);
            invertSelection(fetchDocumentsTableModel);
        });
        applyAllNewButton.addActionListener(e -> controller.handleSymGraphApplyAllNew());
        applyButton.addActionListener(e -> controller.handleSymGraphApplySelected(getSelectedConflicts()));
        pushPreviewButton.addActionListener(e -> controller.handleSymGraphPushPreview());
        pushResetButton.addActionListener(e -> clearPushPreview());
        pushAdvancedToggle.addActionListener(e -> {
            pushAdvancedPanel.setVisible(pushAdvancedToggle.isSelected());
            pushAdvancedPanel.revalidate();
            pushAdvancedPanel.repaint();
        });
        pushButton.addActionListener(e -> controller.handleSymGraphExecutePush());
        pushSelectAllButton.addActionListener(e -> {
            setAllSelected(pushPreviewTableModel, true);
            setAllSelected(pushDocumentsTableModel, true);
        });
        pushDeselectAllButton.addActionListener(e -> {
            setAllSelected(pushPreviewTableModel, false);
            setAllSelected(pushDocumentsTableModel, false);
        });
        pushInvertSelectionButton.addActionListener(e -> {
            invertSelection(pushPreviewTableModel);
            invertSelection(pushDocumentsTableModel);
        });
        confidenceSlider.addChangeListener(e -> confidenceValueLabel.setText(String.format("%.1f", confidenceSlider.getValue() / 100.0)));
        filterNewCheck.addActionListener(e -> rebuildConflictTable());
        filterConflictsCheck.addActionListener(e -> rebuildConflictTable());
        filterSameCheck.addActionListener(e -> rebuildConflictTable());
        conflictTableModel.addTableModelListener(e -> {
            if (e.getColumn() == 0) {
                int row = e.getFirstRow();
                if (row >= 0 && row < displayedConflicts.size()) {
                    boolean selected = Boolean.TRUE.equals(conflictTableModel.getValueAt(row, 0));
                    ConflictEntry conflict = displayedConflicts.get(row);
                    conflict.setSelected(selected);
                    conflictSelectionState.put(conflictKey(conflict), selected);
                }
            }
            updateSelectedCounts();
        });
        fetchDocumentsTableModel.addTableModelListener(e -> updateSelectedCounts());
        pushPreviewTableModel.addTableModelListener(e -> updateSelectedCounts());
        pushDocumentsTableModel.addTableModelListener(e -> updateSelectedCounts());
    }

    private void setAllSelected(DefaultTableModel model, boolean selected) {
        for (int i = 0; i < model.getRowCount(); i++) {
            model.setValueAt(selected, i, 0);
        }
        updateSelectedCounts();
    }

    private void invertSelection(DefaultTableModel model) {
        for (int i = 0; i < model.getRowCount(); i++) {
            Boolean current = (Boolean) model.getValueAt(i, 0);
            model.setValueAt(current == null || !current, i, 0);
        }
        updateSelectedCounts();
    }

    private void selectFetchAction(ConflictAction action) {
        setAllSelected(conflictTableModel, false);
        for (int i = 0; i < displayedConflicts.size() && i < conflictTableModel.getRowCount(); i++) {
            if (displayedConflicts.get(i).getAction() == action) {
                conflictTableModel.setValueAt(true, i, 0);
            }
        }
        updateSelectedCounts();
    }

    private void rebuildConflictTable() {
        conflictTableModel.setRowCount(0);
        displayedConflicts.clear();

        for (ConflictEntry conflict : allConflicts) {
            if (!shouldShowConflict(conflict)) {
                continue;
            }

            boolean selected = conflictSelectionState.getOrDefault(conflictKey(conflict), conflict.isSelected());
            conflict.setSelected(selected);
            conflictTableModel.addRow(new Object[]{
                    selected,
                    conflict.getAddressHex(),
                    formatStorageInfo(conflict),
                    conflict.getLocalNameDisplay(),
                    conflict.getRemoteNameDisplay(),
                    conflict.getAction().getValue().toUpperCase()
            });
            displayedConflicts.add(conflict);
        }

        applyButton.setEnabled(!displayedConflicts.isEmpty() || !displayedFetchDocuments.isEmpty() || graphPreviewData != null);
        updateSelectedCounts();
    }

    private boolean shouldShowConflict(ConflictEntry conflict) {
        return switch (conflict.getAction()) {
            case NEW -> filterNewCheck.isSelected();
            case CONFLICT -> filterConflictsCheck.isSelected();
            case SAME -> filterSameCheck.isSelected();
        };
    }

    private String conflictKey(ConflictEntry conflict) {
        return conflict.getAddressHex() + "|" + conflict.getAction().getValue() + "|" +
                conflict.getLocalNameDisplay() + "|" + conflict.getRemoteNameDisplay();
    }

    private void updateSelectedCounts() {
        int selectedFetch = 0;
        for (int i = 0; i < conflictTableModel.getRowCount(); i++) {
            Boolean selected = (Boolean) conflictTableModel.getValueAt(i, 0);
            if (Boolean.TRUE.equals(selected)) {
                selectedFetch++;
            }
        }
        int selectedFetchDocuments = 0;
        for (int i = 0; i < fetchDocumentsTableModel.getRowCount(); i++) {
            Boolean selected = (Boolean) fetchDocumentsTableModel.getValueAt(i, 0);
            if (Boolean.TRUE.equals(selected)) {
                selectedFetchDocuments++;
            }
        }
        summarySelectedCountLabel.setText(
                "Selected: " + selectedFetch + " symbols / " + selectedFetchDocuments + " docs");

        int selectedPush = 0;
        for (int i = 0; i < pushPreviewTableModel.getRowCount(); i++) {
            Boolean selected = (Boolean) pushPreviewTableModel.getValueAt(i, 0);
            if (Boolean.TRUE.equals(selected)) {
                selectedPush++;
            }
        }
        int selectedPushDocuments = 0;
        for (int i = 0; i < pushDocumentsTableModel.getRowCount(); i++) {
            Boolean selected = (Boolean) pushDocumentsTableModel.getValueAt(i, 0);
            if (Boolean.TRUE.equals(selected)) {
                selectedPushDocuments++;
            }
        }
        pushSelectedCountLabel.setText(
                "Selected: " + selectedPush + " symbols / " + selectedPushDocuments + " docs");
    }

    public void setBinaryInfo(String name, String sha256) {
        binaryNameLabel.setText(name != null ? name : "<no binary loaded>");
        sha256Label.setText(sha256 != null ? sha256 : "<none>");
        localSummaryLabel.setText(sha256 != null ? "Binary metadata available" : "No binary loaded");
    }

    public void setBinaryInfo(String name, String sha256, String localSummary) {
        setBinaryInfo(name, sha256);
        localSummaryLabel.setText(localSummary != null ? localSummary : localSummaryLabel.getText());
    }

    public void setQueryStatus(String status, boolean found) {
        statusLabel.setText(status);
        if (found) {
            statusLabel.setForeground(new Color(0, 128, 0));
            statusBadgeLabel.setText("Found");
            statusBadgeLabel.setBackground(new Color(31, 111, 61));
            statusBadgeLabel.setForeground(Color.WHITE);
        } else if (status.toLowerCase().contains("error") || status.toLowerCase().contains("not found")) {
            statusLabel.setForeground(Color.RED);
            statusBadgeLabel.setText(status.toLowerCase().contains("not found") ? "Not Found" : "Error");
            statusBadgeLabel.setBackground(new Color(139, 46, 46));
            statusBadgeLabel.setForeground(Color.WHITE);
        } else {
            statusLabel.setForeground(Color.GRAY);
            statusBadgeLabel.setText(status.toLowerCase().contains("check") ? "Checking" : "Unknown");
            statusBadgeLabel.setBackground(UIManager.getColor("Panel.background"));
            statusBadgeLabel.setForeground(UIManager.getColor("Label.foreground"));
        }
    }

    public void resetQueryStatus() {
        statusBadgeLabel.setText("Not checked");
        statusBadgeLabel.setBackground(UIManager.getColor("Panel.background"));
        statusBadgeLabel.setForeground(UIManager.getColor("Label.foreground"));
        statusLabel.setForeground(Color.GRAY);
        statusLabel.setText("Use Refresh to check whether this binary already exists in SymGraph.");
        setStorageStatus(null);
    }

    public void setStats(int symbols, int functions, int nodes, int edges, String lastUpdated) {
        setStats(symbols, functions, nodes, edges, lastUpdated, null, null, null);
    }

    public void setStats(
            int symbols,
            int functions,
            int nodes,
            int edges,
            String lastUpdated,
            List<BinaryRevision> revisions,
            Integer latestRevision,
            Integer selectedRevision) {
        symbolsStatLabel.setText(String.format("Symbols: %,d", symbols));
        functionsStatLabel.setText(String.format("Functions: %,d", functions));
        nodesStatLabel.setText(String.format("Graph Nodes: %,d", nodes));
        edgesStatLabel.setText(String.format("Graph Edges: %,d", edges));
        updatedStatLabel.setText("Last Updated: " + (lastUpdated != null ? lastUpdated : "Unknown"));
        latestRevisionLabel.setText(latestRevision != null ? "Latest Version: v" + latestRevision : "Latest Version: -");
        accessibleVersionsLabel.setText(revisions != null ? "Accessible Versions: " + revisions.size() : "Accessible Versions: -");
        statsPanel.setVisible(true);
        setFetchVersions(revisions, selectedRevision);
    }

    public void setFetchVersions(List<BinaryRevision> revisions, Integer selectedRevision) {
        fetchVersionCombo.removeAllItems();
        if (revisions == null || revisions.isEmpty()) {
            fetchVersionCombo.addItem("Latest");
            return;
        }
        String selectedLabel = null;
        for (BinaryRevision revision : revisions) {
            String label = revision.getDisplayLabel();
            fetchVersionCombo.addItem(label);
            if (selectedRevision != null && revision.getVersion() == selectedRevision) {
                selectedLabel = label;
            }
        }
        if (selectedLabel != null) {
            fetchVersionCombo.setSelectedItem(selectedLabel);
        } else {
            fetchVersionCombo.setSelectedIndex(0);
        }
    }

    public void setOpenBinaryUrl(String url) {
        this.openBinaryUrl = url;
        openBinaryButton.setEnabled(url != null && !url.isEmpty());
    }

    public void setStorageStatus(Boolean stored) {
        if (Boolean.TRUE.equals(stored)) {
            storageStatusLabel.setText("Stored Binary: Stored");
            storageStatusLabel.setForeground(new Color(0, 128, 0));
        } else if (Boolean.FALSE.equals(stored)) {
            storageStatusLabel.setText("Stored Binary: Missing");
            storageStatusLabel.setForeground(Color.RED);
        } else {
            storageStatusLabel.setText("Stored Binary: Unknown");
            storageStatusLabel.setForeground(Color.GRAY);
        }
    }

    public boolean isAutoRefreshEnabled() {
        return autoRefreshCheckBox.isSelected();
    }

    public void hideStats() {
        statsPanel.setVisible(false);
        latestRevisionLabel.setText("Latest Version: -");
        accessibleVersionsLabel.setText("Accessible Versions: -");
    }

    public void setPushStatus(String status, Boolean success) {
        pushStatusLabel.setText("Status: " + status);
        if (success == null) {
            pushStatusLabel.setForeground(Color.GRAY);
        } else if (success) {
            pushStatusLabel.setForeground(new Color(0, 128, 0));
        } else {
            pushStatusLabel.setForeground(Color.RED);
        }
    }

    public void showPushProgress(Runnable cancelCallback) {
        this.pushCancelCallback = cancelCallback;
        pushProgressBar.setValue(0);
        pushProgressBar.setVisible(true);
        pushProgressLabel.setVisible(true);
    }

    public void updatePushProgress(int current, int total, String message) {
        int percent = total > 0 ? (int) ((current * 100L) / total) : 0;
        pushProgressBar.setValue(percent);
        pushProgressLabel.setText(message != null ? message : percent + "%");
        pushProgressLabel.setVisible(true);
    }

    public void hidePushProgress() {
        pushProgressBar.setVisible(false);
        pushProgressLabel.setVisible(false);
        pushCancelCallback = null;
    }

    public void setPullStatus(String status, Boolean success) {
        pullStatusLabel.setText(status);
        if (success == null) {
            pullStatusLabel.setForeground(Color.GRAY);
        } else if (success) {
            pullStatusLabel.setForeground(new Color(0, 128, 0));
        } else {
            pullStatusLabel.setForeground(Color.RED);
        }
    }

    public void showPullProgress(String message) {
        fetchProgressBar.setValue(0);
        fetchProgressBar.setVisible(true);
        fetchProgressLabel.setText(message != null ? message : "Fetching...");
        fetchProgressLabel.setVisible(true);
    }

    public void updatePullProgress(int current, int total, String message) {
        int percent = total > 0 ? (current * 100) / total : 0;
        fetchProgressBar.setValue(percent);
        fetchProgressLabel.setText(message != null ? message : percent + "%");
        fetchProgressLabel.setVisible(true);
    }

    public void hidePullProgress() {
        fetchProgressBar.setVisible(false);
        fetchProgressLabel.setVisible(false);
    }

    public void populateConflicts(List<ConflictEntry> conflicts) {
        allConflicts.clear();
        displayedConflicts.clear();
        conflictSelectionState.clear();

        int newCount = 0;
        int conflictCount = 0;
        int sameCount = 0;
        for (ConflictEntry conflict : conflicts) {
            if (conflict.getAction() == ConflictAction.NEW) {
                newCount++;
            } else if (conflict.getAction() == ConflictAction.CONFLICT) {
                conflictCount++;
            } else if (conflict.getAction() == ConflictAction.SAME) {
                sameCount++;
            }
        }
        summaryNewCountLabel.setText("New: " + newCount);
        summaryConflictCountLabel.setText("Conflicts: " + conflictCount);
        summarySameCountLabel.setText("Same: " + sameCount);

        allConflicts.addAll(conflicts);
        allConflicts.sort((a, b) -> {
            int aRank = a.getAction() == ConflictAction.NEW ? 0 : a.getAction() == ConflictAction.CONFLICT ? 1 : 2;
            int bRank = b.getAction() == ConflictAction.NEW ? 0 : b.getAction() == ConflictAction.CONFLICT ? 1 : 2;
            if (aRank != bRank) {
                return Integer.compare(aRank, bRank);
            }
            return Long.compare(a.getAddress(), b.getAddress());
        });

        for (ConflictEntry conflict : allConflicts) {
            boolean selected = conflict.getAction() != ConflictAction.SAME;
            conflict.setSelected(selected);
            conflictSelectionState.put(conflictKey(conflict), selected);
        }

        applyAllNewButton.setEnabled(newCount > 0 || graphPreviewData != null);
        rebuildConflictTable();
    }

    public void populateFetchDocuments(List<DocumentSummary> documents) {
        fetchDocumentsTableModel.setRowCount(0);
        displayedFetchDocuments.clear();

        if (documents != null) {
            for (DocumentSummary document : documents) {
                displayedFetchDocuments.add(document);
                fetchDocumentsTableModel.addRow(new Object[]{
                        true,
                        document.getTitle(),
                        formatSize(document.getContentSizeBytes()),
                        formatDate(document.getCreatedAt()),
                        formatVersion(document.getVersion())
                });
            }
        }

        summaryDocumentCountLabel.setText("Documents: " + displayedFetchDocuments.size());
        updateSelectedCounts();
    }

    private String formatStorageInfo(ConflictEntry conflict) {
        if (conflict == null || conflict.getRemoteSymbol() == null || conflict.getRemoteSymbol().getMetadata() == null) {
            return conflict != null && conflict.getRemoteSymbol() != null ? conflict.getRemoteSymbol().getSymbolType() : "";
        }
        if (!"variable".equals(conflict.getRemoteSymbol().getSymbolType())) {
            return conflict.getRemoteSymbol().getSymbolType();
        }
        Map<String, Object> metadata = conflict.getRemoteSymbol().getMetadata();
        String storageClass = (String) metadata.get("storage_class");
        if ("parameter".equals(storageClass)) {
            return "parameter";
        }
        if ("stack".equals(storageClass)) {
            return "local [stack]";
        }
        if ("register".equals(storageClass)) {
            return "local (reg)";
        }
        return "variable";
    }

    public void setGraphPreviewData(GraphExport export, int nodes, int edges, int communities) {
        this.graphPreviewData = export;
        this.graphPreviewNodes = nodes;
        this.graphPreviewEdges = edges;
        summaryGraphNodesLabel.setText("Graph Nodes: " + nodes);
        summaryGraphEdgesLabel.setText("Graph Edges: " + edges);
        summaryGraphVersionLabel.setText("Version: " + (fetchVersionCombo.getSelectedItem() != null ? fetchVersionCombo.getSelectedItem() : "Latest"));
        if (export != null) {
            StringBuilder summary = new StringBuilder();
            summary.append("Graph preview ready from ")
                    .append(summaryGraphVersionLabel.getText().replace("Version: ", ""))
                    .append(": ")
                    .append(String.format("%,d nodes, %,d edges", nodes, edges));
            if (communities > 0) {
                summary.append(String.format(", %,d communities", communities));
            }
            summary.append(". Merge policy: ").append(graphMergePolicy.replace('_', ' ')).append(".");
            fetchGraphSummaryLabel.setText(summary.toString());
        } else {
            fetchGraphSummaryLabel.setText("No graph data loaded.");
        }
    }

    public GraphExport getGraphPreviewData() {
        return graphPreviewData;
    }

    public String getGraphMergePolicy() {
        return graphMergePolicy;
    }

    public void clearConflicts() {
        allConflicts.clear();
        conflictTableModel.setRowCount(0);
        displayedConflicts.clear();
        conflictSelectionState.clear();
        fetchDocumentsTableModel.setRowCount(0);
        displayedFetchDocuments.clear();
        graphPreviewData = null;
        graphPreviewNodes = 0;
        graphPreviewEdges = 0;
        summaryNewCountLabel.setText("New: 0");
        summaryConflictCountLabel.setText("Conflicts: 0");
        summarySameCountLabel.setText("Same: 0");
        summarySelectedCountLabel.setText("Selected: 0 symbols / 0 docs");
        summaryDocumentCountLabel.setText("Documents: 0");
        summaryGraphNodesLabel.setText("Graph Nodes: 0");
        summaryGraphEdgesLabel.setText("Graph Edges: 0");
        summaryGraphVersionLabel.setText("Version: -");
        fetchGraphSummaryLabel.setText("No graph data loaded.");
        hidePullProgress();
        pullStatusLabel.setText("");
    }

    public List<ConflictEntry> getAllNewConflicts() {
        List<ConflictEntry> results = new ArrayList<>();
        for (ConflictEntry conflict : allConflicts) {
            boolean selected = conflictSelectionState.getOrDefault(conflictKey(conflict), conflict.isSelected());
            conflict.setSelected(selected);
            if (conflict.getAction() == ConflictAction.NEW) {
                results.add(conflict);
            }
        }
        return results;
    }

    public List<ConflictEntry> getSelectedConflicts() {
        List<ConflictEntry> results = new ArrayList<>();
        for (ConflictEntry conflict : displayedConflicts) {
            boolean selected = conflictSelectionState.getOrDefault(conflictKey(conflict), conflict.isSelected());
            conflict.setSelected(selected);
            if (selected) {
                results.add(conflict);
            }
        }
        return results;
    }

    public List<DocumentSummary> getSelectedFetchDocuments() {
        List<DocumentSummary> results = new ArrayList<>();
        for (int i = 0; i < fetchDocumentsTableModel.getRowCount() && i < displayedFetchDocuments.size(); i++) {
            if (Boolean.TRUE.equals(fetchDocumentsTableModel.getValueAt(i, 0))) {
                results.add(displayedFetchDocuments.get(i));
            }
        }
        return results;
    }

    public void showApplyingPage(String message) {
        fetchProgressBar.setVisible(true);
        fetchProgressBar.setValue(0);
        fetchProgressLabel.setVisible(true);
        fetchProgressLabel.setText(message != null ? message : "Applying...");
    }

    public void updateApplyProgress(int current, int total, String message) {
        int percent = total > 0 ? (int) ((current * 100L) / total) : 0;
        fetchProgressBar.setValue(percent);
        fetchProgressLabel.setText(message != null ? message : percent + "%");
    }

    public void hideApplyProgress() {
        fetchProgressBar.setVisible(false);
        fetchProgressLabel.setVisible(false);
    }

    public void showCompletePage(String message, boolean success) {
        setPullStatus(message != null ? message : "Operation complete", success);
        hideApplyProgress();
    }

    public void setButtonsEnabled(boolean enabled) {
        queryButton.setEnabled(enabled);
        uploadBinaryButton.setEnabled(enabled);
        pullPreviewButton.setEnabled(enabled);
        fetchResetButton.setEnabled(enabled);
        applyButton.setEnabled(enabled);
        applyAllNewButton.setEnabled(enabled);
        pushPreviewButton.setEnabled(enabled);
        pushResetButton.setEnabled(enabled);
        pushButton.setEnabled(enabled);
        selectAllButton.setEnabled(enabled);
        deselectAllButton.setEnabled(enabled);
        selectNewButton.setEnabled(enabled);
        selectConflictsButton.setEnabled(enabled);
        invertSelectionButton.setEnabled(enabled);
        pushSelectAllButton.setEnabled(enabled);
        pushDeselectAllButton.setEnabled(enabled);
        pushInvertSelectionButton.setEnabled(enabled);
        openBinaryButton.setEnabled(enabled && openBinaryUrl != null && !openBinaryUrl.isEmpty());
    }

    public PullConfig getPullConfig() {
        List<String> types = new ArrayList<>();
        if (pullFunctionsCheck.isSelected()) types.add("function");
        if (pullVariablesCheck.isSelected()) types.add("variable");
        if (pullTypesCheck.isSelected()) types.add("type");
        if (pullCommentsCheck.isSelected()) types.add("comment");
        Integer version = parseSelectedVersion((String) fetchVersionCombo.getSelectedItem());
        return new PullConfig(types, confidenceSlider.getValue() / 100.0, pullGraphCheck.isSelected(),
                version, fetchNameFilterField.getText().trim());
    }

    public PushConfig getPushConfig() {
        List<String> types = new ArrayList<>();
        if (pushFunctionsCheck.isSelected()) types.add("function");
        if (pushVariablesCheck.isSelected()) types.add("variable");
        if (pushTypesCheck.isSelected()) types.add("type");
        if (pushCommentsCheck.isSelected()) types.add("comment");
        return new PushConfig(
                fullBinaryRadio.isSelected() ? PushScope.FULL_BINARY.getValue() : PushScope.CURRENT_FUNCTION.getValue(),
                types,
                pushNameFilterField.getText().trim(),
                pushGraphCheck.isSelected(),
                "Private".equals(pushVisibilityCombo.getSelectedItem()) ? "private" : "public");
    }

    private Integer parseSelectedVersion(String label) {
        if (label == null || label.isEmpty() || !label.startsWith("v")) {
            return null;
        }
        String digits = label.substring(1).split(" ")[0];
        try {
            return Integer.parseInt(digits);
        } catch (NumberFormatException e) {
            return null;
        }
    }

    public void clearPushPreview() {
        pushPreviewSymbols.clear();
        pushPreviewDocuments.clear();
        pushGraphData = null;
        pushGraphNodes = 0;
        pushGraphEdges = 0;
        pushPreviewTableModel.setRowCount(0);
        pushDocumentsTableModel.setRowCount(0);
        pushMatchingCountLabel.setText("Matching: 0");
        pushSelectedCountLabel.setText("Selected: 0 symbols / 0 docs");
        pushDocumentsCountLabel.setText("Documents: 0");
        pushGraphNodesLabel.setText("Graph Nodes: 0");
        pushGraphEdgesLabel.setText("Graph Edges: 0");
        pushGraphSummaryLabel.setText("No graph data included in this publish preview.");
        setPushStatus("Ready", null);
    }

    public void setPushPreview(
            List<Map<String, Object>> symbols,
            Map<String, Object> graphData,
            int nodes,
            int edges,
            List<Map<String, Object>> documents) {
        pushPreviewSymbols.clear();
        pushPreviewSymbols.addAll(symbols);
        pushPreviewDocuments.clear();
        if (documents != null) {
            pushPreviewDocuments.addAll(documents);
        }
        pushGraphData = graphData;
        pushGraphNodes = nodes;
        pushGraphEdges = edges;
        pushPreviewTableModel.setRowCount(0);
        pushDocumentsTableModel.setRowCount(0);

        for (Map<String, Object> symbol : symbols) {
            long address = parseAddress(symbol.get("address"));
            String name = (String) symbol.getOrDefault("name", symbol.getOrDefault("content", "<unnamed>"));
            String type = (String) symbol.getOrDefault("symbol_type", "function");
            double confidence = symbol.get("confidence") instanceof Number
                    ? ((Number) symbol.get("confidence")).doubleValue()
                    : 0.0;
            String provenance = (String) symbol.getOrDefault("provenance", "unknown");
            pushPreviewTableModel.addRow(new Object[]{
                    true,
                    String.format("0x%x", address),
                    type,
                    name,
                    String.format("%.2f", confidence),
                    provenance
            });
        }

        for (Map<String, Object> document : pushPreviewDocuments) {
            pushDocumentsTableModel.addRow(new Object[]{
                    true,
                    document.getOrDefault("title", "Untitled"),
                    formatSize(document.get("size_bytes")),
                    formatDate(valueAsString(document.get("updated_at"))),
                    formatVersion(document.get("version")),
                    toDocumentTypeLabel(valueAsString(document.get("doc_type")))
            });
        }

        pushMatchingCountLabel.setText("Matching: " + symbols.size());
        pushDocumentsCountLabel.setText("Documents: " + pushPreviewDocuments.size());
        pushGraphNodesLabel.setText("Graph Nodes: " + nodes);
        pushGraphEdgesLabel.setText("Graph Edges: " + edges);
        if (graphData != null) {
            pushGraphSummaryLabel.setText(String.format(
                    "Graph preview ready for publish: %,d nodes, %,d edges.", nodes, edges));
        } else {
            pushGraphSummaryLabel.setText("No graph data included in this publish preview.");
        }
        updateSelectedCounts();
    }

    public List<Map<String, Object>> getSelectedPushSymbols() {
        List<Map<String, Object>> results = new ArrayList<>();
        for (int i = 0; i < pushPreviewTableModel.getRowCount() && i < pushPreviewSymbols.size(); i++) {
            if (Boolean.TRUE.equals(pushPreviewTableModel.getValueAt(i, 0))) {
                results.add(pushPreviewSymbols.get(i));
            }
        }
        return results;
    }

    public List<Map<String, Object>> getSelectedPushDocuments() {
        List<Map<String, Object>> results = new ArrayList<>();
        for (int i = 0; i < pushDocumentsTableModel.getRowCount() && i < pushPreviewDocuments.size(); i++) {
            if (Boolean.TRUE.equals(pushDocumentsTableModel.getValueAt(i, 0))) {
                Map<String, Object> document = new java.util.HashMap<>(pushPreviewDocuments.get(i));
                document.put("doc_type", toDocumentTypeValue((String) pushDocumentsTableModel.getValueAt(i, 5)));
                results.add(document);
            }
        }
        return results;
    }

    private String toDocumentTypeLabel(String docType) {
        if (docType == null) {
            return "Notes";
        }

        return switch (docType) {
            case "general" -> "General";
            case "malware_report" -> "Malware Report";
            case "vuln_analysis" -> "Vulnerability Analysis";
            case "api_doc", "protocol_spec" -> "API Documentation";
            default -> "Notes";
        };
    }

    private String toDocumentTypeValue(String label) {
        if (label == null) {
            return "notes";
        }

        return switch (label) {
            case "General" -> "general";
            case "Malware Report" -> "malware_report";
            case "Vulnerability Analysis" -> "vuln_analysis";
            case "API Documentation" -> "api_doc";
            default -> "notes";
        };
    }

    public Map<String, Object> getPushGraphData() {
        return pushGraphData;
    }

    private long parseAddress(Object value) {
        if (value instanceof Number) {
            return ((Number) value).longValue();
        }
        if (value instanceof String) {
            String text = ((String) value).trim();
            try {
                if (text.startsWith("0x") || text.startsWith("0X")) {
                    return Long.parseUnsignedLong(text.substring(2), 16);
                }
                return Long.parseLong(text);
            } catch (NumberFormatException ignored) {
            }
        }
        return 0L;
    }

    private String formatSize(Object sizeValue) {
        long size = 0;
        if (sizeValue instanceof Number) {
            size = ((Number) sizeValue).longValue();
        } else if (sizeValue instanceof String) {
            try {
                size = Long.parseLong((String) sizeValue);
            } catch (NumberFormatException ignored) {
                return sizeValue.toString();
            }
        }
        if (size >= 1024) {
            return String.format("%.1f KB", size / 1024.0);
        }
        return size + " B";
    }

    private String formatVersion(Object versionValue) {
        if (versionValue instanceof Number) {
            return "v" + ((Number) versionValue).intValue();
        }
        if (versionValue instanceof String && !((String) versionValue).isEmpty()) {
            String value = (String) versionValue;
            return value.startsWith("v") ? value : "v" + value;
        }
        return "New";
    }

    private String formatDate(String value) {
        if (value == null || value.isEmpty()) {
            return "-";
        }
        return value.length() > 10 ? value.substring(0, 10) : value;
    }

    private String valueAsString(Object value) {
        return value != null ? value.toString() : null;
    }

    public static class PullConfig {
        private final List<String> symbolTypes;
        private final double minConfidence;
        private final boolean includeGraph;
        private final Integer version;
        private final String nameFilter;

        public PullConfig(List<String> symbolTypes, double minConfidence, boolean includeGraph,
                          Integer version, String nameFilter) {
            this.symbolTypes = symbolTypes;
            this.minConfidence = minConfidence;
            this.includeGraph = includeGraph;
            this.version = version;
            this.nameFilter = nameFilter;
        }

        public List<String> getSymbolTypes() { return symbolTypes; }
        public double getMinConfidence() { return minConfidence; }
        public boolean isIncludeGraph() { return includeGraph; }
        public Integer getVersion() { return version; }
        public String getNameFilter() { return nameFilter; }
    }

    public static class PushConfig {
        private final String scope;
        private final List<String> symbolTypes;
        private final String nameFilter;
        private final boolean pushGraph;
        private final String visibility;

        public PushConfig(String scope, List<String> symbolTypes, String nameFilter,
                          boolean pushGraph, String visibility) {
            this.scope = scope;
            this.symbolTypes = symbolTypes;
            this.nameFilter = nameFilter;
            this.pushGraph = pushGraph;
            this.visibility = visibility;
        }

        public String getScope() { return scope; }
        public List<String> getSymbolTypes() { return symbolTypes; }
        public String getNameFilter() { return nameFilter; }
        public boolean isPushGraph() { return pushGraph; }
        public String getVisibility() { return visibility; }
    }
}
