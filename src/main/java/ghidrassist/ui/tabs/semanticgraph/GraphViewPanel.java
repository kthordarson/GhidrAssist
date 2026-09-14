package ghidrassist.ui.tabs.semanticgraph;

import javax.swing.*;
import java.awt.*;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.awt.event.MouseWheelEvent;
import java.awt.event.MouseWheelListener;
import java.awt.geom.AffineTransform;
import java.awt.geom.CubicCurve2D;
import java.awt.geom.Path2D;
import java.awt.geom.RoundRectangle2D;
import java.awt.image.BufferedImage;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Queue;
import java.util.Set;
import java.util.TreeMap;

import ghidra.util.Msg;

import ghidrassist.core.MarkdownHelper;
import ghidrassist.core.TabController;
import ghidrassist.ui.tabs.SemanticGraphTab;
import ghidrassist.graphrag.nodes.KnowledgeNode;
import ghidrassist.graphrag.BinaryKnowledgeGraph.GraphEdge;
import ghidrassist.graphrag.nodes.EdgeType;

/**
 * Visual graph sub-panel for the Semantic Graph tab.
 * Uses custom Java2D rendering with cubic bezier edges and BFS layout.
 */
public class GraphViewPanel extends JPanel {
    private static final long serialVersionUID = 1L;

    private final TabController controller;
    private final SemanticGraphTab parentTab;

    // Custom canvas
    private GraphCanvas canvas;
    private JScrollBar hScrollBar;
    private JScrollBar vScrollBar;
    private boolean updatingScrollbars = false;

    // Content bounds in world coords (set by buildGraph)
    private double contentMinX, contentMinY, contentMaxX, contentMaxY;

    // Controls
    private JSpinner nHopsSpinner;
    private JCheckBox showCallsCheckbox;
    private JCheckBox showVulnCheckbox;
    private JCheckBox showNetworkCheckbox;

    // Zoom controls
    private JButton zoomInButton;
    private JButton zoomOutButton;
    private JButton zoomFitButton;
    private JLabel zoomLabel;

    // Selected node info panel
    private JLabel selectedNodeLabel;
    private JEditorPane summaryPane;
    private JScrollPane summaryScrollPane;
    private MarkdownHelper markdownHelper;

    // Not-indexed placeholder
    private JPanel notIndexedPanel;
    private JPanel contentPanel;
    private CardLayout cardLayout;

    // Selected node
    private KnowledgeNode selectedNode = null;

    // ===== Color constants (matching BinAssist/IDAssist/SymGraph web UI) =====
    private static final Color BG_COLOR = new Color(0x03, 0x07, 0x12);           // #030712

    // Node fills
    private static final Color CENTER_FILL = new Color(0x25, 0x63, 0xEB);        // #2563EB
    private static final Color CALLER_FILL = new Color(0x06, 0xB6, 0xD4);        // #06B6D4
    private static final Color VULN_HIGH_FILL = new Color(0x99, 0x1B, 0x1B);     // #991B1B
    private static final Color VULN_MEDIUM_FILL = new Color(0x92, 0x40, 0x0E);   // #92400E
    private static final Color NORMAL_FILL = new Color(0x37, 0x41, 0x51);        // #374151
    private static final Color EXTERNAL_FILL = new Color(0x4B, 0x55, 0x63);     // #4B5563

    // Node strokes
    private static final Color CENTER_STROKE = new Color(0x3B, 0x82, 0xF6);      // #3B82F6
    private static final Color CALLER_STROKE = new Color(0x22, 0xD3, 0xEE);      // #22D3EE
    private static final Color VULN_STROKE = new Color(0xDC, 0x26, 0x26);        // #DC2626
    private static final Color VULN_MEDIUM_STROKE = new Color(0xF5, 0x9E, 0x0B); // #F59E0B
    private static final Color NORMAL_STROKE = new Color(0x4B, 0x55, 0x63);      // #4B5563
    private static final Color EXTERNAL_STROKE = new Color(0x6B, 0x72, 0x80);   // #6B7280
    private static final Color SELECTED_STROKE = new Color(0x22, 0xD3, 0xEE);    // #22D3EE

    // Node text
    private static final Color CENTER_TEXT = Color.WHITE;
    private static final Color CALLER_TEXT = Color.WHITE;
    private static final Color VULN_HIGH_TEXT = new Color(0xFC, 0xA5, 0xA5);     // #FCA5A5
    private static final Color VULN_MEDIUM_TEXT = new Color(0xFD, 0xE6, 0x8A);   // #FDE68A
    private static final Color NORMAL_TEXT = new Color(0xE6, 0xE6, 0xE6);        // #E6E6E6

    // Edge colors
    private static final Color EDGE_CALLS = new Color(0x22, 0xD3, 0xEE);         // #22D3EE
    private static final Color EDGE_REFS = new Color(0x60, 0xA5, 0xFA);          // #60A5FA
    private static final Color EDGE_VULN = new Color(0xDC, 0x26, 0x26);          // #DC2626
    private static final Color EDGE_NETWORK = new Color(0x06, 0xB6, 0xD4);       // #06B6D4
    private static final Color EDGE_TAINT = new Color(0xF9, 0x73, 0x16);         // #F97316
    private static final Color EDGE_CONTAINS = new Color(0xA7, 0x8B, 0xFA);      // #A78BFA
    private static final Color EDGE_FLOWS = new Color(0xF4, 0x72, 0xB6);         // #F472B6
    private static final Color EDGE_LABEL_COLOR = new Color(0x9C, 0xA3, 0xAF);   // #9CA3AF

    // ===== Inner Data Classes =====

    private static class NodeRect {
        KnowledgeNode node;
        double x, y, width;
        boolean isCenter, isCaller;
        Color fillColor, strokeColor, textColor;
        float strokeWidth;
        String line1, line2, vulnLabel;
    }

    private static class EdgePath {
        GraphEdge edge;
        double srcX, srcY, tgtX, tgtY;
        Color color;
        float strokeWidth;
        boolean dashed;
        String label;
    }

    // ===== GraphCanvas Inner Class =====

    private class GraphCanvas extends JPanel
            implements java.awt.event.MouseListener, java.awt.event.MouseMotionListener, MouseWheelListener {

        private static final int NODE_WIDTH_MIN = 140;
        private static final int NODE_WIDTH_MAX = 420;
        private static final int NODE_HEIGHT = 50;
        private static final int NODE_RADIUS = 4;
        private static final int HORIZONTAL_GAP = 30;
        private static final int VERTICAL_GAP = 80;
        private static final float ARROW_SIZE = 8.0f;
        private static final float NODE_TEXT_SCALE = 0.8f;
        private static final float EDGE_LABEL_SCALE = 0.7f;

        double scale = 1.0;
        double translateX = 0;
        double translateY = 0;
        List<NodeRect> nodeRects = new ArrayList<>();
        List<EdgePath> edgePaths = new ArrayList<>();
        NodeRect selectedNodeRect = null;
        Point lastMousePt = null;
        boolean panning = false;

        GraphCanvas() {
            setOpaque(true);
            setBackground(BG_COLOR);
            addMouseListener(this);
            addMouseMotionListener(this);
            addMouseWheelListener(this);
        }

        @Override
        protected void paintComponent(Graphics g) {
            super.paintComponent(g);
            Graphics2D g2 = (Graphics2D) g.create();

            // Clip to component bounds to prevent painting outside during partial repaints
            g2.clipRect(0, 0, getWidth(), getHeight());

            // Anti-aliasing
            g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
            g2.setRenderingHint(RenderingHints.KEY_TEXT_ANTIALIASING, RenderingHints.VALUE_TEXT_ANTIALIAS_ON);
            g2.setRenderingHint(RenderingHints.KEY_STROKE_CONTROL, RenderingHints.VALUE_STROKE_PURE);

            // Fill background
            g2.setColor(BG_COLOR);
            g2.fillRect(0, 0, getWidth(), getHeight());

            // Apply transform relative to Swing's base transform (never use setTransform)
            g2.translate(getWidth() / 2.0 + translateX, getHeight() / 2.0 + translateY);
            g2.scale(scale, scale);

            // Draw edges (z-order: behind nodes)
            for (EdgePath ep : edgePaths) {
                drawEdge(g2, ep);
            }

            // Draw nodes (z-order: on top)
            for (NodeRect nr : nodeRects) {
                drawNode(g2, nr);
            }

            g2.dispose();
        }

        private void drawEdge(Graphics2D g2, EdgePath ep) {
            double midY = (ep.srcY + ep.tgtY) / 2.0;

            // Cubic bezier: moveTo(srcX,srcY) cubicTo(srcX,midY, tgtX,midY, tgtX,tgtY)
            CubicCurve2D.Double curve = new CubicCurve2D.Double(
                ep.srcX, ep.srcY,
                ep.srcX, midY,
                ep.tgtX, midY,
                ep.tgtX, ep.tgtY
            );

            Stroke edgeStroke;
            if (ep.dashed) {
                edgeStroke = new BasicStroke(ep.strokeWidth, BasicStroke.CAP_BUTT,
                    BasicStroke.JOIN_MITER, 10.0f, new float[]{6.0f, 4.0f}, 0.0f);
            } else {
                edgeStroke = new BasicStroke(ep.strokeWidth, BasicStroke.CAP_ROUND, BasicStroke.JOIN_ROUND);
            }
            g2.setStroke(edgeStroke);
            g2.setColor(ep.color);
            g2.draw(curve);

            // Edge label at curve midpoint
            double labelX = (ep.srcX + ep.tgtX) / 2.0;
            double labelY = midY - 8;
            if (ep.label != null && !ep.label.isEmpty()) {
                Font baseFont = g2.getFont();
                Font labelFont = baseFont.deriveFont(baseFont.getSize2D() * EDGE_LABEL_SCALE);
                g2.setFont(labelFont);
                FontMetrics fm = g2.getFontMetrics();
                float textWidth = fm.stringWidth(ep.label);
                g2.setColor(EDGE_LABEL_COLOR);
                g2.drawString(ep.label, (float)(labelX - textWidth / 2.0), (float)labelY);
                g2.setFont(baseFont);
            }

            // Arrowhead: tangent at t=1 is from (tgtX, midY) to (tgtX, tgtY)
            drawArrowhead(g2, ep.tgtX, midY, ep.tgtX, ep.tgtY, ep.color);
        }

        private void drawArrowhead(Graphics2D g2, double fromX, double fromY, double toX, double toY, Color color) {
            double dx = toX - fromX;
            double dy = toY - fromY;
            double length = Math.hypot(dx, dy);
            if (length == 0) return;

            double ux = dx / length;
            double uy = dy / length;

            double leftX = toX - ARROW_SIZE * ux + (ARROW_SIZE / 2.0) * uy;
            double leftY = toY - ARROW_SIZE * uy - (ARROW_SIZE / 2.0) * ux;
            double rightX = toX - ARROW_SIZE * ux - (ARROW_SIZE / 2.0) * uy;
            double rightY = toY - ARROW_SIZE * uy + (ARROW_SIZE / 2.0) * ux;

            Path2D.Double arrow = new Path2D.Double();
            arrow.moveTo(toX, toY);
            arrow.lineTo(leftX, leftY);
            arrow.lineTo(rightX, rightY);
            arrow.closePath();

            g2.setColor(color);
            g2.setStroke(new BasicStroke(1.0f));
            g2.fill(arrow);
        }

        private void drawNode(Graphics2D g2, NodeRect nr) {
            RoundRectangle2D.Double rect = new RoundRectangle2D.Double(
                nr.x, nr.y, nr.width, NODE_HEIGHT, NODE_RADIUS, NODE_RADIUS
            );

            // Fill
            g2.setColor(nr.fillColor);
            g2.fill(rect);

            // Stroke
            Color stroke = (selectedNodeRect == nr) ? SELECTED_STROKE : nr.strokeColor;
            float sw = (selectedNodeRect == nr) ? 2.0f : nr.strokeWidth;
            g2.setColor(stroke);
            g2.setStroke(new BasicStroke(sw));
            g2.draw(rect);

            // Text: line1 (name) and line2 (address)
            Font baseFont = g2.getFont();
            Font nodeFont = baseFont.deriveFont(Font.BOLD, baseFont.getSize2D() * NODE_TEXT_SCALE);
            g2.setFont(nodeFont);
            g2.setColor(nr.textColor);
            FontMetrics fm = g2.getFontMetrics();

            float textX = (float)(nr.x + 6);
            float textY = (float)(nr.y + fm.getAscent() + 4);

            if (nr.line1 != null) {
                // Clip text to node width
                String clipped = clipText(nr.line1, fm, (int)(nr.width - 12));
                g2.drawString(clipped, textX, textY);
            }
            if (nr.line2 != null) {
                Font addrFont = baseFont.deriveFont(baseFont.getSize2D() * NODE_TEXT_SCALE);
                g2.setFont(addrFont);
                FontMetrics fm2 = g2.getFontMetrics();
                String clipped = clipText(nr.line2, fm2, (int)(nr.width - 12));
                g2.drawString(clipped, textX, textY + fm.getHeight() + 2);
            }

            // Vuln label
            if (nr.vulnLabel != null) {
                Font vulnFont = baseFont.deriveFont(Font.BOLD, baseFont.getSize2D() * NODE_TEXT_SCALE * 0.85f);
                g2.setFont(vulnFont);
                g2.setColor(VULN_HIGH_TEXT);
                FontMetrics fmv = g2.getFontMetrics();
                float vx = (float)(nr.x + nr.width - fmv.stringWidth(nr.vulnLabel) - 6);
                float vy = (float)(nr.y + NODE_HEIGHT - 6);
                g2.drawString(nr.vulnLabel, vx, vy);
            }

            g2.setFont(baseFont);
        }

        private String clipText(String text, FontMetrics fm, int maxWidth) {
            if (fm.stringWidth(text) <= maxWidth) return text;
            String ellipsis = "...";
            int ellipsisWidth = fm.stringWidth(ellipsis);
            for (int i = text.length() - 1; i > 0; i--) {
                if (fm.stringWidth(text.substring(0, i)) + ellipsisWidth <= maxWidth) {
                    return text.substring(0, i) + ellipsis;
                }
            }
            return ellipsis;
        }

        // ===== Mouse Interaction =====

        private NodeRect hitTest(int screenX, int screenY) {
            // Transform screen coords to world coords
            double wx = (screenX - getWidth() / 2.0 - translateX) / scale;
            double wy = (screenY - getHeight() / 2.0 - translateY) / scale;

            // Reverse iteration for top-most z-order
            for (int i = nodeRects.size() - 1; i >= 0; i--) {
                NodeRect nr = nodeRects.get(i);
                if (wx >= nr.x && wx <= nr.x + nr.width &&
                    wy >= nr.y && wy <= nr.y + NODE_HEIGHT) {
                    return nr;
                }
            }
            return null;
        }

        @Override
        public void mouseClicked(MouseEvent e) {
            NodeRect hit = hitTest(e.getX(), e.getY());
            if (hit != null) {
                selectNode(hit);
                if (e.getClickCount() == 2 && hit.node.getAddress() != null) {
                    parentTab.navigateToFunction(hit.node.getAddress());
                }
            } else {
                clearSelection();
            }
        }

        @Override
        public void mousePressed(MouseEvent e) {
            lastMousePt = e.getPoint();
            NodeRect hit = hitTest(e.getX(), e.getY());
            panning = (hit == null);
        }

        @Override
        public void mouseReleased(MouseEvent e) {
            lastMousePt = null;
            panning = false;
        }

        @Override
        public void mouseDragged(MouseEvent e) {
            if (lastMousePt != null && panning) {
                int dx = e.getX() - lastMousePt.x;
                int dy = e.getY() - lastMousePt.y;
                translateX += dx;
                translateY += dy;
                lastMousePt = e.getPoint();
                syncScrollbars();
                repaint();
            }
        }

        @Override
        public void mouseWheelMoved(MouseWheelEvent e) {
            if (e.isControlDown()) {
                // Zoom toward cursor
                double factor = (e.getWheelRotation() < 0) ? 1.2 : 1.0 / 1.2;
                double mouseX = e.getX() - getWidth() / 2.0 - translateX;
                double mouseY = e.getY() - getHeight() / 2.0 - translateY;

                translateX -= mouseX * (factor - 1);
                translateY -= mouseY * (factor - 1);
                scale *= factor;

                updateZoomLabel();
                syncScrollbars();
                repaint();
            } else {
                // Scroll = pan vertically
                translateY -= e.getWheelRotation() * 30;
                syncScrollbars();
                repaint();
            }
        }

        @Override public void mouseEntered(MouseEvent e) {}
        @Override public void mouseExited(MouseEvent e) {}
        @Override public void mouseMoved(MouseEvent e) {}

        // ===== Zoom helpers =====

        void zoomToFit() {
            if (nodeRects.isEmpty()) return;

            double minX = Double.MAX_VALUE, minY = Double.MAX_VALUE;
            double maxX = -Double.MAX_VALUE, maxY = -Double.MAX_VALUE;
            for (NodeRect nr : nodeRects) {
                if (nr.x < minX) minX = nr.x;
                if (nr.y < minY) minY = nr.y;
                if (nr.x + nr.width > maxX) maxX = nr.x + nr.width;
                if (nr.y + NODE_HEIGHT > maxY) maxY = nr.y + NODE_HEIGHT;
            }

            double contentW = maxX - minX;
            double contentH = maxY - minY;
            if (contentW <= 0 || contentH <= 0) return;

            double fitMargin = 40;
            double availW = getWidth() - fitMargin * 2;
            double availH = getHeight() - fitMargin * 2;
            if (availW <= 0 || availH <= 0) return;

            scale = Math.min(availW / contentW, availH / contentH);
            scale = Math.max(0.1, Math.min(scale, 3.0));

            double centerX = (minX + maxX) / 2.0;
            double centerY = (minY + maxY) / 2.0;
            translateX = -centerX * scale;
            translateY = -centerY * scale;
        }
    }

    // ===== Constructor =====

    public GraphViewPanel(TabController controller, SemanticGraphTab parentTab) {
        super(new BorderLayout());
        this.controller = controller;
        this.parentTab = parentTab;
        canvas = new GraphCanvas();
        initializeComponents();
        layoutComponents();
        setupListeners();
    }

    private void initializeComponents() {
        // N-Hops spinner
        SpinnerNumberModel spinnerModel = new SpinnerNumberModel(2, 1, 5, 1);
        nHopsSpinner = new JSpinner(spinnerModel);
        nHopsSpinner.setPreferredSize(new Dimension(75, 25));

        // Edge type checkboxes
        showCallsCheckbox = new JCheckBox("CALLS", true);
        showVulnCheckbox = new JCheckBox("VULN", true);
        showNetworkCheckbox = new JCheckBox("NETWORK", true);

        // Zoom controls
        zoomInButton = new JButton("+");
        zoomInButton.setToolTipText("Zoom In");
        zoomInButton.setMargin(new Insets(2, 6, 2, 6));

        zoomOutButton = new JButton("-");
        zoomOutButton.setToolTipText("Zoom Out");
        zoomOutButton.setMargin(new Insets(2, 6, 2, 6));

        zoomFitButton = new JButton("Fit");
        zoomFitButton.setToolTipText("Fit to View");
        zoomFitButton.setMargin(new Insets(2, 6, 2, 6));

        zoomLabel = new JLabel("100%");
        zoomLabel.setToolTipText("Current zoom level (CTRL+Wheel to zoom)");

        // Scrollbars for panning
        hScrollBar = new JScrollBar(JScrollBar.HORIZONTAL);
        vScrollBar = new JScrollBar(JScrollBar.VERTICAL);

        // Markdown helper for rendering summaries
        markdownHelper = new MarkdownHelper();

        // Selected node info
        selectedNodeLabel = new JLabel("Double-click a node to navigate");
        selectedNodeLabel.setForeground(UIManager.getColor("Label.disabledForeground"));

        // Summary pane for rendering markdown
        summaryPane = new JEditorPane();
        summaryPane.setContentType("text/html");
        summaryPane.setEditable(false);
        summaryPane.setOpaque(false);
        summaryPane.putClientProperty(JEditorPane.HONOR_DISPLAY_PROPERTIES, Boolean.TRUE);
        summaryPane.setFont(UIManager.getFont("Label.font"));

        summaryScrollPane = new JScrollPane(summaryPane);
        summaryScrollPane.setBorder(BorderFactory.createEmptyBorder());
        summaryScrollPane.setPreferredSize(new Dimension(400, 120));
        summaryScrollPane.getVerticalScrollBar().setUnitIncrement(16);

        // Not indexed placeholder
        notIndexedPanel = createNotIndexedPanel();

        // Card layout
        cardLayout = new CardLayout();
        contentPanel = new JPanel(cardLayout);
    }

    private JPanel createNotIndexedPanel() {
        JPanel panel = new JPanel(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.gridx = 0;
        gbc.gridy = 0;
        gbc.insets = new Insets(10, 10, 10, 10);

        JLabel messageLabel = new JLabel("<html><center>Function not yet indexed in<br>the knowledge graph.</center></html>");
        messageLabel.setHorizontalAlignment(SwingConstants.CENTER);
        panel.add(messageLabel, gbc);

        gbc.gridy = 1;
        JButton indexButton = new JButton("Index This Function");
        indexButton.addActionListener(e -> controller.handleSemanticGraphIndexFunction(parentTab.getCurrentAddress()));
        panel.add(indexButton, gbc);

        gbc.gridy = 2;
        JLabel orLabel = new JLabel("Or index the entire binary:");
        panel.add(orLabel, gbc);

        gbc.gridy = 3;
        JButton reindexButton = new JButton("ReIndex Binary");
        reindexButton.addActionListener(e -> controller.handleSemanticGraphReindex());
        panel.add(reindexButton, gbc);

        return panel;
    }

    private void layoutComponents() {
        // ===== Main content panel =====
        JPanel mainContent = new JPanel(new BorderLayout(5, 5));
        mainContent.setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5));

        // ===== Top controls =====
        JPanel controlsPanel = new JPanel(new BorderLayout());

        // Left side: N-Hops and Edge Types
        JPanel leftControls = new JPanel(new FlowLayout(FlowLayout.LEFT, 10, 5));
        leftControls.add(new JLabel("N-Hops:"));
        leftControls.add(nHopsSpinner);
        leftControls.add(Box.createHorizontalStrut(10));
        leftControls.add(new JLabel("Edge Types:"));
        leftControls.add(showCallsCheckbox);
        leftControls.add(showVulnCheckbox);
        leftControls.add(showNetworkCheckbox);

        // Right side: Zoom controls
        JPanel zoomControls = new JPanel(new FlowLayout(FlowLayout.RIGHT, 5, 5));
        zoomControls.add(new JLabel("Zoom:"));
        zoomControls.add(zoomOutButton);
        zoomControls.add(zoomLabel);
        zoomControls.add(zoomInButton);
        zoomControls.add(zoomFitButton);

        controlsPanel.add(leftControls, BorderLayout.WEST);
        controlsPanel.add(zoomControls, BorderLayout.EAST);

        mainContent.add(controlsPanel, BorderLayout.NORTH);

        // ===== Selected node info and summary (bottom) =====
        JPanel infoPanel = new JPanel(new BorderLayout(5, 5));
        infoPanel.setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5));

        infoPanel.add(selectedNodeLabel, BorderLayout.NORTH);
        infoPanel.add(summaryScrollPane, BorderLayout.CENTER);

        // ===== Canvas with scrollbars =====
        JPanel canvasPanel = new JPanel(new BorderLayout());
        canvasPanel.add(canvas, BorderLayout.CENTER);
        canvasPanel.add(vScrollBar, BorderLayout.EAST);
        canvasPanel.add(hScrollBar, BorderLayout.SOUTH);

        // ===== Resizable split between graph canvas and summary =====
        JSplitPane splitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT, canvasPanel, infoPanel);
        splitPane.setResizeWeight(0.8);
        splitPane.setContinuousLayout(true);
        splitPane.setBorder(BorderFactory.createEmptyBorder());

        mainContent.add(splitPane, BorderLayout.CENTER);

        // ===== Card layout setup =====
        contentPanel.add(mainContent, "content");
        contentPanel.add(notIndexedPanel, "notIndexed");

        add(contentPanel, BorderLayout.CENTER);

        // Default to not indexed
        cardLayout.show(contentPanel, "notIndexed");
    }

    private void setupListeners() {
        // N-Hops change
        nHopsSpinner.addChangeListener(e -> refresh());

        // Edge type filters
        showCallsCheckbox.addActionListener(e -> refresh());
        showVulnCheckbox.addActionListener(e -> refresh());
        showNetworkCheckbox.addActionListener(e -> refresh());

        // Zoom button handlers
        zoomInButton.addActionListener(e -> {
            canvas.scale *= 1.2;
            updateZoomLabel();
            syncScrollbars();
            canvas.repaint();
        });

        zoomOutButton.addActionListener(e -> {
            canvas.scale /= 1.2;
            updateZoomLabel();
            syncScrollbars();
            canvas.repaint();
        });

        zoomFitButton.addActionListener(e -> {
            canvas.zoomToFit();
            updateZoomLabel();
            syncScrollbars();
            canvas.repaint();
        });

        // Scrollbar listeners
        hScrollBar.addAdjustmentListener(e -> {
            if (!updatingScrollbars) {
                canvas.translateX = -e.getValue();
                canvas.repaint();
            }
        });
        vScrollBar.addAdjustmentListener(e -> {
            if (!updatingScrollbars) {
                canvas.translateY = -e.getValue();
                canvas.repaint();
            }
        });
    }

    // ===== Public Methods =====

    public void refresh() {
        int nHops = (Integer) nHopsSpinner.getValue();
        Set<EdgeType> edgeTypes = getSelectedEdgeTypes();
        controller.handleSemanticGraphVisualRefresh(this, parentTab.getCurrentAddress(), nHops, edgeTypes);
    }

    public void showNotIndexed() {
        cardLayout.show(contentPanel, "notIndexed");
    }

    public void showContent() {
        cardLayout.show(contentPanel, "content");
    }

    /**
     * Build and display the graph with the given nodes and edges.
     */
    public void buildGraph(KnowledgeNode centerNode, List<KnowledgeNode> nodes, List<GraphEdge> edges) {
        // Clear canvas
        canvas.nodeRects.clear();
        canvas.edgePaths.clear();
        canvas.selectedNodeRect = null;
        selectedNode = null;

        if (nodes.isEmpty()) {
            canvas.repaint();
            return;
        }

        // Filter out unlinked nodes (nodes with no edges), keeping center node
        Set<String> linkedNodeIds = new HashSet<>();
        linkedNodeIds.add(centerNode.getId());
        for (GraphEdge edge : edges) {
            linkedNodeIds.add(edge.getSourceId());
            linkedNodeIds.add(edge.getTargetId());
        }
        List<KnowledgeNode> linkedNodes = new ArrayList<>();
        for (KnowledgeNode n : nodes) {
            if (linkedNodeIds.contains(n.getId())) {
                linkedNodes.add(n);
            }
        }
        nodes = linkedNodes;

        // Build node ID -> node map
        Map<String, KnowledgeNode> nodeMap = new HashMap<>();
        for (KnowledgeNode n : nodes) {
            nodeMap.put(n.getId(), n);
        }

        // Identify caller IDs (nodes that CALL the center node)
        Set<String> callerIds = new HashSet<>();
        for (GraphEdge edge : edges) {
            if (edge.getType() == EdgeType.CALLS &&
                edge.getTargetId().equals(centerNode.getId())) {
                callerIds.add(edge.getSourceId());
            }
        }

        // Compute node sizes using FontMetrics
        Map<String, Double> nodeSizes = computeNodeSizes(nodes);

        // BFS layout
        int nHops = (Integer) nHopsSpinner.getValue();
        Map<String, double[]> positions = layoutNodes(centerNode, nodes, edges, nodeSizes, nHops);

        // Build NodeRect list with styling
        Map<String, NodeRect> nodeRectMap = new HashMap<>();
        for (KnowledgeNode node : nodes) {
            NodeRect nr = new NodeRect();
            nr.node = node;
            double[] pos = positions.get(node.getId());
            nr.x = pos != null ? pos[0] : 0;
            nr.y = pos != null ? pos[1] : 0;
            nr.width = nodeSizes.getOrDefault(node.getId(), (double) GraphCanvas.NODE_WIDTH_MIN);
            nr.isCenter = node.getId().equals(centerNode.getId());
            nr.isCaller = callerIds.contains(node.getId());

            // 5-tier styling
            applyNodeStyle(nr, node);

            // Text lines
            String name = node.getName();
            boolean isExternal = node.getAddress() == null;
            if (name == null || name.isEmpty()) {
                name = isExternal ? "[Unknown External]" : "0x" + Long.toHexString(node.getAddress());
            }
            nr.line1 = name;
            nr.line2 = isExternal ? "[EXTERNAL]" : "0x" + Long.toHexString(node.getAddress());

            if (node.hasSecurityFlags()) {
                String risk = node.getRiskLevel();
                if (risk != null && (risk.equalsIgnoreCase("HIGH") || risk.equalsIgnoreCase("CRITICAL"))) {
                    nr.vulnLabel = "[VULN]";
                }
            }

            canvas.nodeRects.add(nr);
            nodeRectMap.put(node.getId(), nr);
        }

        // Compute edge paths with horizontal offset distribution
        computeEdgePaths(edges, nodeRectMap);

        // Reset transform and center on center node
        double[] centerPos = positions.get(centerNode.getId());
        double centerWidth = nodeSizes.getOrDefault(centerNode.getId(), (double) GraphCanvas.NODE_WIDTH_MIN);
        canvas.scale = 1.0;
        if (centerPos != null) {
            canvas.translateX = -(centerPos[0] + centerWidth / 2.0) * canvas.scale;
            canvas.translateY = -(centerPos[1] + GraphCanvas.NODE_HEIGHT / 2.0) * canvas.scale;
        } else {
            canvas.translateX = 0;
            canvas.translateY = 0;
        }

        updateContentBounds();
        updateZoomLabel();
        syncScrollbars();
        canvas.repaint();

        // Select center node
        NodeRect centerRect = nodeRectMap.get(centerNode.getId());
        if (centerRect != null) {
            selectNode(centerRect);
        }
    }

    // ===== Layout Algorithm =====

    private Map<String, double[]> layoutNodes(KnowledgeNode centerNode, List<KnowledgeNode> nodes,
            List<GraphEdge> edges, Map<String, Double> nodeSizes, int maxHops) {

        Set<String> nodeIds = new HashSet<>();
        for (KnowledgeNode n : nodes) {
            nodeIds.add(n.getId());
        }

        // Build adjacency
        Map<String, Set<String>> outgoing = new HashMap<>();
        Map<String, Set<String>> incoming = new HashMap<>();
        for (GraphEdge edge : edges) {
            String src = edge.getSourceId();
            String tgt = edge.getTargetId();
            if (nodeIds.contains(src) && nodeIds.contains(tgt)) {
                outgoing.computeIfAbsent(src, k -> new HashSet<>()).add(tgt);
                incoming.computeIfAbsent(tgt, k -> new HashSet<>()).add(src);
            }
        }

        String centerId = centerNode.getId();

        // Identify callers (direct incoming to center)
        Set<String> callerIds = new HashSet<>();
        if (incoming.containsKey(centerId)) {
            for (String src : incoming.get(centerId)) {
                if (!src.equals(centerId)) {
                    callerIds.add(src);
                }
            }
        }

        // BFS callees (mark callers + center as visited)
        Set<String> visited = new HashSet<>(callerIds);
        visited.add(centerId);

        Map<String, Integer> levels = new HashMap<>();
        levels.put(centerId, 0);

        Set<String> frontier = new HashSet<>();
        frontier.add(centerId);

        for (int depth = 1; depth <= maxHops; depth++) {
            Set<String> nextFrontier = new HashSet<>();
            for (String nid : frontier) {
                Set<String> neighbors = outgoing.get(nid);
                if (neighbors == null) continue;
                for (String neighbor : neighbors) {
                    if (!visited.contains(neighbor)) {
                        visited.add(neighbor);
                        levels.put(neighbor, depth);
                        nextFrontier.add(neighbor);
                    }
                }
            }
            frontier = nextFrontier;
        }

        // Callers at level -1
        for (String cid : callerIds) {
            levels.put(cid, -1);
        }

        // Unvisited nodes at level 0
        for (KnowledgeNode node : nodes) {
            levels.putIfAbsent(node.getId(), 0);
        }

        // Group by level using TreeMap for sorted iteration
        TreeMap<Integer, List<KnowledgeNode>> levelMap = new TreeMap<>();
        for (KnowledgeNode node : nodes) {
            int level = levels.get(node.getId());
            levelMap.computeIfAbsent(level, k -> new ArrayList<>()).add(node);
        }

        // Position each level, centered at x=0
        Map<String, double[]> positions = new HashMap<>();
        for (Map.Entry<Integer, List<KnowledgeNode>> entry : levelMap.entrySet()) {
            int level = entry.getKey();
            List<KnowledgeNode> levelNodes = entry.getValue();

            // Sort alphabetically
            levelNodes.sort(Comparator.comparing(n -> n.getName() != null ? n.getName() : ""));

            // Compute total width
            double totalWidth = 0;
            for (int i = 0; i < levelNodes.size(); i++) {
                double w = nodeSizes.getOrDefault(levelNodes.get(i).getId(), (double) GraphCanvas.NODE_WIDTH_MIN);
                totalWidth += w;
                if (i < levelNodes.size() - 1) {
                    totalWidth += GraphCanvas.HORIZONTAL_GAP;
                }
            }

            double currentX = -totalWidth / 2.0;
            double y = level * (GraphCanvas.NODE_HEIGHT + GraphCanvas.VERTICAL_GAP);

            for (KnowledgeNode node : levelNodes) {
                double w = nodeSizes.getOrDefault(node.getId(), (double) GraphCanvas.NODE_WIDTH_MIN);
                positions.put(node.getId(), new double[]{currentX, y});
                currentX += w + GraphCanvas.HORIZONTAL_GAP;
            }
        }

        return positions;
    }

    // ===== Node Size Computation =====

    private Map<String, Double> computeNodeSizes(List<KnowledgeNode> nodes) {
        // Use a temp BufferedImage for FontMetrics measurement
        BufferedImage img = new BufferedImage(1, 1, BufferedImage.TYPE_INT_ARGB);
        Graphics2D g2 = img.createGraphics();
        Font baseFont = g2.getFont();
        Font nodeFont = baseFont.deriveFont(Font.BOLD, baseFont.getSize2D() * GraphCanvas.NODE_TEXT_SCALE);
        g2.setFont(nodeFont);
        FontMetrics fm = g2.getFontMetrics();

        Map<String, Double> sizes = new HashMap<>();
        double padding = 20.0;

        for (KnowledgeNode node : nodes) {
            String name = node.getName();
            boolean isExternal = node.getAddress() == null;
            if (name == null || name.isEmpty()) {
                name = isExternal ? "[Unknown External]" : "0x" + Long.toHexString(node.getAddress());
            }
            String addr = isExternal ? "[EXTERNAL]" : "0x" + Long.toHexString(node.getAddress());

            double nameW = fm.stringWidth(name) + padding;
            double addrW = fm.stringWidth(addr) + padding;
            double width = Math.max(nameW, addrW);
            width = Math.max(GraphCanvas.NODE_WIDTH_MIN, Math.min(GraphCanvas.NODE_WIDTH_MAX, width));
            sizes.put(node.getId(), width);
        }

        g2.dispose();
        return sizes;
    }

    // ===== Edge Path Computation (ported from BinAssist) =====

    private void computeEdgePaths(List<GraphEdge> edges, Map<String, NodeRect> nodeRectMap) {
        // Determine connection sides and group edges per (node, side)
        Map<Integer, String[]> edgeSides = new HashMap<>(); // idx -> [srcSide, tgtSide]
        // Key: "nodeId:side", Value: list of (otherEndpointX, edgeIdx)
        Map<String, List<double[]>> sideEdges = new HashMap<>();

        for (int idx = 0; idx < edges.size(); idx++) {
            GraphEdge edge = edges.get(idx);
            NodeRect src = nodeRectMap.get(edge.getSourceId());
            NodeRect tgt = nodeRectMap.get(edge.getTargetId());
            if (src == null || tgt == null) continue;

            double srcCenterX = src.x + src.width / 2.0;
            double srcCenterY = src.y + GraphCanvas.NODE_HEIGHT / 2.0;
            double tgtCenterX = tgt.x + tgt.width / 2.0;
            double tgtCenterY = tgt.y + GraphCanvas.NODE_HEIGHT / 2.0;

            String srcSide, tgtSide;
            if (tgtCenterY >= srcCenterY) {
                srcSide = "bottom";
                tgtSide = "top";
            } else {
                srcSide = "top";
                tgtSide = "bottom";
            }
            edgeSides.put(idx, new String[]{srcSide, tgtSide});

            String srcKey = edge.getSourceId() + ":" + srcSide;
            String tgtKey = edge.getTargetId() + ":" + tgtSide;
            sideEdges.computeIfAbsent(srcKey, k -> new ArrayList<>()).add(new double[]{tgtCenterX, idx});
            sideEdges.computeIfAbsent(tgtKey, k -> new ArrayList<>()).add(new double[]{srcCenterX, idx});
        }

        // Compute horizontal offsets per edge per side
        Map<String, Double> edgeOffsets = new HashMap<>(); // "nodeId:side:edgeIdx" -> offset
        for (Map.Entry<String, List<double[]>> entry : sideEdges.entrySet()) {
            String key = entry.getKey();
            String nodeId = key.substring(0, key.lastIndexOf(':'));
            List<double[]> entries = entry.getValue();

            NodeRect nr = nodeRectMap.get(nodeId);
            double nodeWidth = (nr != null) ? nr.width : GraphCanvas.NODE_WIDTH_MIN;

            int count = entries.size();
            entries.sort(Comparator.comparingDouble(a -> a[0]));

            double available = Math.max(10.0, nodeWidth - 20.0);
            double[] offsets;
            if (count == 1) {
                offsets = new double[]{0.0};
            } else {
                offsets = new double[count];
                double step = available / (count - 1);
                for (int i = 0; i < count; i++) {
                    offsets[i] = -(available / 2.0) + step * i;
                }
            }

            for (int i = 0; i < count; i++) {
                int edgeIdx = (int) entries.get(i)[1];
                String side = key.substring(key.lastIndexOf(':') + 1);
                edgeOffsets.put(nodeId + ":" + side + ":" + edgeIdx, offsets[i]);
            }
        }

        // Build EdgePath list
        for (int idx = 0; idx < edges.size(); idx++) {
            GraphEdge edge = edges.get(idx);
            NodeRect src = nodeRectMap.get(edge.getSourceId());
            NodeRect tgt = nodeRectMap.get(edge.getTargetId());
            if (src == null || tgt == null) continue;

            String[] sides = edgeSides.get(idx);
            if (sides == null) continue;

            String srcSide = sides[0];
            String tgtSide = sides[1];

            Double srcOffset = edgeOffsets.get(edge.getSourceId() + ":" + srcSide + ":" + idx);
            Double tgtOffset = edgeOffsets.get(edge.getTargetId() + ":" + tgtSide + ":" + idx);
            if (srcOffset == null) srcOffset = 0.0;
            if (tgtOffset == null) tgtOffset = 0.0;

            double srcX = src.x + src.width / 2.0 + srcOffset;
            double tgtX = tgt.x + tgt.width / 2.0 + tgtOffset;
            double srcY = srcSide.equals("top") ? src.y : src.y + GraphCanvas.NODE_HEIGHT;
            double tgtY = tgtSide.equals("top") ? tgt.y : tgt.y + GraphCanvas.NODE_HEIGHT;

            EdgePath ep = new EdgePath();
            ep.edge = edge;
            ep.srcX = srcX;
            ep.srcY = srcY;
            ep.tgtX = tgtX;
            ep.tgtY = tgtY;
            ep.label = edge.getType().getDisplayName();

            // Edge styling
            applyEdgeStyle(ep, edge.getType());

            canvas.edgePaths.add(ep);
        }
    }

    // ===== Styling =====

    private void applyNodeStyle(NodeRect nr, KnowledgeNode node) {
        if (nr.isCenter) {
            nr.fillColor = CENTER_FILL;
            nr.strokeColor = CENTER_STROKE;
            nr.textColor = CENTER_TEXT;
            nr.strokeWidth = 2.0f;
        } else if (node.hasSecurityFlags()) {
            String risk = node.getRiskLevel();
            if (risk != null && (risk.equalsIgnoreCase("HIGH") || risk.equalsIgnoreCase("CRITICAL"))) {
                nr.fillColor = VULN_HIGH_FILL;
                nr.strokeColor = VULN_STROKE;
                nr.textColor = VULN_HIGH_TEXT;
                nr.strokeWidth = 2.0f;
            } else {
                nr.fillColor = VULN_MEDIUM_FILL;
                nr.strokeColor = VULN_MEDIUM_STROKE;
                nr.textColor = VULN_MEDIUM_TEXT;
                nr.strokeWidth = 1.5f;
            }
        } else if (nr.isCaller) {
            nr.fillColor = CALLER_FILL;
            nr.strokeColor = CALLER_STROKE;
            nr.textColor = CALLER_TEXT;
            nr.strokeWidth = 1.5f;
        } else if (node.getType() == ghidrassist.graphrag.nodes.NodeType.EXTERNAL) {
            nr.fillColor = EXTERNAL_FILL;
            nr.strokeColor = EXTERNAL_STROKE;
            nr.textColor = NORMAL_TEXT;
            nr.strokeWidth = 1.0f;
        } else {
            nr.fillColor = NORMAL_FILL;
            nr.strokeColor = NORMAL_STROKE;
            nr.textColor = NORMAL_TEXT;
            nr.strokeWidth = 1.0f;
        }
    }

    private void applyEdgeStyle(EdgePath ep, EdgeType type) {
        ep.dashed = false;
        ep.strokeWidth = 1.5f;
        switch (type) {
            case CALLS:
                ep.color = EDGE_CALLS;
                break;
            case INFERRED_CALLS:
                ep.color = EDGE_CALLS;
                ep.dashed = true;
                ep.strokeWidth = 1.0f;
                break;
            case REFERENCES:
                ep.color = EDGE_REFS;
                ep.dashed = true;
                ep.strokeWidth = 1.0f;
                break;
            case CALLS_VULNERABLE:
                ep.color = EDGE_VULN;
                break;
            case NETWORK_SEND:
            case NETWORK_RECV:
                ep.color = EDGE_NETWORK;
                break;
            case TAINT_FLOWS_TO:
                ep.color = EDGE_TAINT;
                break;
            case VULNERABLE_VIA:
                ep.color = EDGE_VULN;
                ep.dashed = true;
                break;
            case CONTAINS:
                ep.color = EDGE_CONTAINS;
                ep.dashed = true;
                ep.strokeWidth = 1.0f;
                break;
            case FLOWS_TO:
                ep.color = EDGE_FLOWS;
                ep.strokeWidth = 1.0f;
                break;
            default:
                ep.color = EDGE_CALLS;
                break;
        }
    }

    // ===== Selection =====

    private void selectNode(NodeRect nr) {
        canvas.selectedNodeRect = nr;
        selectedNode = nr.node;

        String addrStr = nr.node.getAddress() != null
            ? "@ 0x" + Long.toHexString(nr.node.getAddress())
            : "[EXTERNAL]";
        selectedNodeLabel.setText(nr.node.getName() + " " + addrStr + "  (double-click to navigate)");
        selectedNodeLabel.setForeground(UIManager.getColor("Label.foreground"));

        String summary = nr.node.getLlmSummary();
        if (summary != null && !summary.isEmpty()) {
            String html = markdownHelper.markdownToHtmlSimple(summary);
            summaryPane.setText(html);
            summaryPane.setCaretPosition(0);
        } else {
            summaryPane.setText("<html><body><i style='color:gray'>No summary available</i></body></html>");
        }

        canvas.repaint();
    }

    private void clearSelection() {
        canvas.selectedNodeRect = null;
        selectedNode = null;
        selectedNodeLabel.setText("Double-click a node to navigate");
        selectedNodeLabel.setForeground(UIManager.getColor("Label.disabledForeground"));
        summaryPane.setText("");
        canvas.repaint();
    }

    // ===== Helpers =====

    private Set<EdgeType> getSelectedEdgeTypes() {
        Set<EdgeType> types = new HashSet<>();
        if (showCallsCheckbox.isSelected()) {
            types.add(EdgeType.CALLS);
            types.add(EdgeType.INFERRED_CALLS);
            types.add(EdgeType.REFERENCES);
        }
        if (showVulnCheckbox.isSelected()) {
            types.add(EdgeType.CALLS_VULNERABLE);
            types.add(EdgeType.TAINT_FLOWS_TO);
            types.add(EdgeType.VULNERABLE_VIA);
        }
        if (showNetworkCheckbox.isSelected()) {
            types.add(EdgeType.NETWORK_SEND);
            types.add(EdgeType.NETWORK_RECV);
        }
        return types;
    }

    private void updateZoomLabel() {
        int percentage = (int) Math.round(canvas.scale * 100);
        zoomLabel.setText(percentage + "%");
    }

    /**
     * Update content bounding box from current nodeRects.
     */
    private void updateContentBounds() {
        if (canvas.nodeRects.isEmpty()) {
            contentMinX = contentMinY = contentMaxX = contentMaxY = 0;
            return;
        }
        contentMinX = Double.MAX_VALUE;
        contentMinY = Double.MAX_VALUE;
        contentMaxX = -Double.MAX_VALUE;
        contentMaxY = -Double.MAX_VALUE;
        for (NodeRect nr : canvas.nodeRects) {
            if (nr.x < contentMinX) contentMinX = nr.x;
            if (nr.y < contentMinY) contentMinY = nr.y;
            if (nr.x + nr.width > contentMaxX) contentMaxX = nr.x + nr.width;
            if (nr.y + GraphCanvas.NODE_HEIGHT > contentMaxY) contentMaxY = nr.y + GraphCanvas.NODE_HEIGHT;
        }
    }

    /**
     * Sync scrollbar range and position with the current canvas transform and content bounds.
     */
    private void syncScrollbars() {
        updatingScrollbars = true;
        try {
            int margin = 200;
            double s = canvas.scale;
            int W = Math.max(1, canvas.getWidth());
            int H = Math.max(1, canvas.getHeight());

            // Horizontal: scrollbar value = -translateX
            // Content spans [contentMinX*s, contentMaxX*s] in "screen offset from center" coords
            // We want scrollbar range to allow panning so all content is reachable
            int hMin = (int)(contentMinX * s - W / 2.0 - margin);
            int hMax = (int)(contentMaxX * s + W / 2.0 + margin);
            int hValue = (int)(-canvas.translateX);
            int hExtent = W;

            hValue = Math.max(hMin, Math.min(hValue, hMax - hExtent));
            hScrollBar.setValues(hValue, hExtent, hMin, hMax);
            hScrollBar.setUnitIncrement(20);
            hScrollBar.setBlockIncrement(W / 2);

            // Vertical: scrollbar value = -translateY
            int vMin = (int)(contentMinY * s - H / 2.0 - margin);
            int vMax = (int)(contentMaxY * s + H / 2.0 + margin);
            int vValue = (int)(-canvas.translateY);
            int vExtent = H;

            vValue = Math.max(vMin, Math.min(vValue, vMax - vExtent));
            vScrollBar.setValues(vValue, vExtent, vMin, vMax);
            vScrollBar.setUnitIncrement(20);
            vScrollBar.setBlockIncrement(H / 2);
        } finally {
            updatingScrollbars = false;
        }
    }
}
