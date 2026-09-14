package ghidrassist.services.symgraph;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Data models for SymGraph API integration.
 */
public class SymGraphModels {

    /**
     * Action type for conflict resolution during pull.
     */
    public enum ConflictAction {
        NEW("new"),           // Remote only, doesn't exist locally
        CONFLICT("conflict"), // Different values locally and remotely
        SAME("same");         // Identical values locally and remotely

        private final String value;

        ConflictAction(String value) {
            this.value = value;
        }

        public String getValue() {
            return value;
        }
    }

    /**
     * Scope for push operations.
     */
    public enum PushScope {
        FULL_BINARY("full"),
        CURRENT_FUNCTION("function");

        private final String value;

        PushScope(String value) {
            this.value = value;
        }

        public String getValue() {
            return value;
        }
    }

    /**
     * Statistics for a binary in SymGraph.
     */
    public static class BinaryStats {
        private int symbolCount;
        private int functionCount;
        private int graphNodeCount;
        private int graphEdgeCount;
        private int queryCount;
        private String lastQueriedAt;

        public BinaryStats() {}

        public BinaryStats(int symbolCount, int functionCount, int graphNodeCount, int graphEdgeCount,
                          int queryCount, String lastQueriedAt) {
            this.symbolCount = symbolCount;
            this.functionCount = functionCount;
            this.graphNodeCount = graphNodeCount;
            this.graphEdgeCount = graphEdgeCount;
            this.queryCount = queryCount;
            this.lastQueriedAt = lastQueriedAt;
        }

        public int getSymbolCount() { return symbolCount; }
        public void setSymbolCount(int symbolCount) { this.symbolCount = symbolCount; }
        public int getFunctionCount() { return functionCount; }
        public void setFunctionCount(int functionCount) { this.functionCount = functionCount; }
        public int getGraphNodeCount() { return graphNodeCount; }
        public void setGraphNodeCount(int graphNodeCount) { this.graphNodeCount = graphNodeCount; }
        public int getGraphEdgeCount() { return graphEdgeCount; }
        public void setGraphEdgeCount(int graphEdgeCount) { this.graphEdgeCount = graphEdgeCount; }
        public int getQueryCount() { return queryCount; }
        public void setQueryCount(int queryCount) { this.queryCount = queryCount; }
        public String getLastQueriedAt() { return lastQueriedAt; }
        public void setLastQueriedAt(String lastQueriedAt) { this.lastQueriedAt = lastQueriedAt; }
    }

    public static class BinaryUploadResult {
        private String sha256;
        private String binaryId;
        private long fileSize;
        private boolean isNew;
        private String message;
        private boolean metadataExtracted;

        public String getSha256() { return sha256; }
        public void setSha256(String sha256) { this.sha256 = sha256; }
        public String getBinaryId() { return binaryId; }
        public void setBinaryId(String binaryId) { this.binaryId = binaryId; }
        public long getFileSize() { return fileSize; }
        public void setFileSize(long fileSize) { this.fileSize = fileSize; }
        public boolean isNew() { return isNew; }
        public void setNew(boolean aNew) { isNew = aNew; }
        public String getMessage() { return message; }
        public void setMessage(String message) { this.message = message; }
        public boolean isMetadataExtracted() { return metadataExtracted; }
        public void setMetadataExtracted(boolean metadataExtracted) { this.metadataExtracted = metadataExtracted; }
    }

    /**
     * Accessible binary revision metadata.
     */
    public static class BinaryRevision {
        private int version;
        private String createdAt;
        private String visibility;
        private boolean latest;
        private String ownerUsername;

        public int getVersion() { return version; }
        public void setVersion(int version) { this.version = version; }
        public String getCreatedAt() { return createdAt; }
        public void setCreatedAt(String createdAt) { this.createdAt = createdAt; }
        public String getVisibility() { return visibility; }
        public void setVisibility(String visibility) { this.visibility = visibility; }
        public boolean isLatest() { return latest; }
        public void setLatest(boolean latest) { this.latest = latest; }
        public String getOwnerUsername() { return ownerUsername; }
        public void setOwnerUsername(String ownerUsername) { this.ownerUsername = ownerUsername; }

        public String getDisplayLabel() {
            return latest ? "v" + version + " (Latest)" : "v" + version;
        }
    }

    /**
     * A symbol from SymGraph.
     */
    public static class Symbol {
        private long address;
        private String symbolType;
        private String name;
        private String dataType;
        private double confidence;
        private String provenance;
        private String source;
        private String content;  // For comments - stores the comment text
        private Map<String, Object> metadata;

        public Symbol() {}

        public Symbol(long address, String symbolType, String name,
                     double confidence, String provenance) {
            this.address = address;
            this.symbolType = symbolType;
            this.name = name;
            this.confidence = confidence;
            this.provenance = provenance;
        }

        public long getAddress() { return address; }
        public void setAddress(long address) { this.address = address; }
        public String getSymbolType() { return symbolType; }
        public void setSymbolType(String symbolType) { this.symbolType = symbolType; }
        public String getName() { return name; }
        public void setName(String name) { this.name = name; }
        public String getDataType() { return dataType; }
        public void setDataType(String dataType) { this.dataType = dataType; }
        public double getConfidence() { return confidence; }
        public void setConfidence(double confidence) { this.confidence = confidence; }
        public String getProvenance() { return provenance; }
        public void setProvenance(String provenance) { this.provenance = provenance; }
        public String getSource() { return source; }
        public void setSource(String source) { this.source = source; }
        public String getContent() { return content; }
        public void setContent(String content) { this.content = content; }

        /**
         * Get the display name for this symbol.
         * For comments (which have no name), returns the content field.
         * For other symbols, returns the name.
         */
        public String getDisplayName() {
            if (name != null && !name.isEmpty()) {
                return name;
            }
            if (content != null && !content.isEmpty()) {
                return content;
            }
            return null;
        }
        public Map<String, Object> getMetadata() { return metadata; }
        public void setMetadata(Map<String, Object> metadata) { this.metadata = metadata; }
    }

    /**
     * A graph node from SymGraph.
     */
    public static class GraphNode {
        private String id;
        private long address;
        private String nodeType;
        private String name;
        private String signature;
        private String decompiledCode;
        private String disassembly;
        private String summary;
        private Map<String, Object> properties;

        public GraphNode() {}

        public String getId() { return id; }
        public void setId(String id) { this.id = id; }
        public long getAddress() { return address; }
        public void setAddress(long address) { this.address = address; }
        public String getNodeType() { return nodeType; }
        public void setNodeType(String nodeType) { this.nodeType = nodeType; }
        public String getName() { return name; }
        public void setName(String name) { this.name = name; }
        public String getSignature() { return signature; }
        public void setSignature(String signature) { this.signature = signature; }
        public String getDecompiledCode() { return decompiledCode; }
        public void setDecompiledCode(String decompiledCode) { this.decompiledCode = decompiledCode; }
        public String getDisassembly() { return disassembly; }
        public void setDisassembly(String disassembly) { this.disassembly = disassembly; }
        public String getSummary() { return summary; }
        public void setSummary(String summary) { this.summary = summary; }
        public Map<String, Object> getProperties() { return properties; }
        public void setProperties(Map<String, Object> properties) { this.properties = properties; }
    }

    /**
     * A graph edge from SymGraph.
     */
    public static class GraphEdge {
        private long sourceAddress;
        private long targetAddress;
        private String sourceName;
        private String targetName;
        private String edgeType;
        private Map<String, Object> properties;

        public GraphEdge() {}

        public GraphEdge(long sourceAddress, long targetAddress, String edgeType) {
            this.sourceAddress = sourceAddress;
            this.targetAddress = targetAddress;
            this.edgeType = edgeType;
        }

        public long getSourceAddress() { return sourceAddress; }
        public void setSourceAddress(long sourceAddress) { this.sourceAddress = sourceAddress; }
        public long getTargetAddress() { return targetAddress; }
        public void setTargetAddress(long targetAddress) { this.targetAddress = targetAddress; }
        public String getSourceName() { return sourceName; }
        public void setSourceName(String sourceName) { this.sourceName = sourceName; }
        public String getTargetName() { return targetName; }
        public void setTargetName(String targetName) { this.targetName = targetName; }
        public String getEdgeType() { return edgeType; }
        public void setEdgeType(String edgeType) { this.edgeType = edgeType; }
        public Map<String, Object> getProperties() { return properties; }
        public void setProperties(Map<String, Object> properties) { this.properties = properties; }
    }

    /**
     * Exported graph data from SymGraph.
     */
    public static class GraphExport {
        private String binarySha256;
        private List<GraphNode> nodes;
        private List<GraphEdge> edges;
        private String exportVersion;
        private Map<String, Object> metadata;

        public String getBinarySha256() { return binarySha256; }
        public void setBinarySha256(String binarySha256) { this.binarySha256 = binarySha256; }
        public List<GraphNode> getNodes() { return nodes != null ? nodes : new ArrayList<>(); }
        public void setNodes(List<GraphNode> nodes) { this.nodes = nodes; }
        public List<GraphEdge> getEdges() { return edges != null ? edges : new ArrayList<>(); }
        public void setEdges(List<GraphEdge> edges) { this.edges = edges; }
        public String getExportVersion() { return exportVersion; }
        public void setExportVersion(String exportVersion) { this.exportVersion = exportVersion; }
        public Map<String, Object> getMetadata() { return metadata; }
        public void setMetadata(Map<String, Object> metadata) { this.metadata = metadata; }
    }

    /**
     * Document summary for list views.
     */
    public static class DocumentSummary {
        private String id;
        private String documentIdentityId;
        private int version;
        private String title;
        private String docType;
        private int contentSizeBytes;
        private String createdAt;

        public String getId() { return id; }
        public void setId(String id) { this.id = id; }
        public String getDocumentIdentityId() { return documentIdentityId; }
        public void setDocumentIdentityId(String documentIdentityId) { this.documentIdentityId = documentIdentityId; }
        public int getVersion() { return version; }
        public void setVersion(int version) { this.version = version; }
        public String getTitle() { return title; }
        public void setTitle(String title) { this.title = title; }
        public String getDocType() { return docType; }
        public void setDocType(String docType) { this.docType = docType; }
        public int getContentSizeBytes() { return contentSizeBytes; }
        public void setContentSizeBytes(int contentSizeBytes) { this.contentSizeBytes = contentSizeBytes; }
        public String getCreatedAt() { return createdAt; }
        public void setCreatedAt(String createdAt) { this.createdAt = createdAt; }
    }

    /**
     * Full document with content.
     */
    public static class Document extends DocumentSummary {
        private String content;

        public String getContent() { return content; }
        public void setContent(String content) { this.content = content; }
    }

    /**
     * Result for a single pushed document.
     */
    public static class DocumentPushResult {
        private String status;
        private String documentIdentityId;
        private int version;
        private String message;
        private Document document;

        public String getStatus() { return status; }
        public void setStatus(String status) { this.status = status; }
        public String getDocumentIdentityId() { return documentIdentityId; }
        public void setDocumentIdentityId(String documentIdentityId) { this.documentIdentityId = documentIdentityId; }
        public int getVersion() { return version; }
        public void setVersion(int version) { this.version = version; }
        public String getMessage() { return message; }
        public void setMessage(String message) { this.message = message; }
        public Document getDocument() { return document; }
        public void setDocument(Document document) { this.document = document; }
    }

    /**
     * An entry in the conflict resolution table.
     */
    public static class ConflictEntry {
        private long address;
        private String localName;
        private String remoteName;
        private ConflictAction action;
        private boolean selected;
        private Symbol remoteSymbol;

        public ConflictEntry() {}

        public ConflictEntry(long address, String localName, String remoteName,
                            ConflictAction action, boolean selected, Symbol remoteSymbol) {
            this.address = address;
            this.localName = localName;
            this.remoteName = remoteName;
            this.action = action;
            this.selected = selected;
            this.remoteSymbol = remoteSymbol;
        }

        public static ConflictEntry createNew(long address, Symbol remoteSymbol) {
            return new ConflictEntry(address, null, remoteSymbol.getDisplayName(),
                    ConflictAction.NEW, true, remoteSymbol);
        }

        public static ConflictEntry createConflict(long address, String localName, Symbol remoteSymbol) {
            return new ConflictEntry(address, localName, remoteSymbol.getDisplayName(),
                    ConflictAction.CONFLICT, false, remoteSymbol);
        }

        public static ConflictEntry createSame(long address, String name, Symbol remoteSymbol) {
            return new ConflictEntry(address, name, name,
                    ConflictAction.SAME, true, remoteSymbol);
        }

        public long getAddress() { return address; }
        public void setAddress(long address) { this.address = address; }
        public String getLocalName() { return localName; }
        public void setLocalName(String localName) { this.localName = localName; }
        public String getRemoteName() { return remoteName; }
        public void setRemoteName(String remoteName) { this.remoteName = remoteName; }
        public ConflictAction getAction() { return action; }
        public void setAction(ConflictAction action) { this.action = action; }
        public boolean isSelected() { return selected; }
        public void setSelected(boolean selected) { this.selected = selected; }
        public Symbol getRemoteSymbol() { return remoteSymbol; }
        public void setRemoteSymbol(Symbol remoteSymbol) { this.remoteSymbol = remoteSymbol; }

        public String getAddressHex() {
            return String.format("0x%x", address);
        }

        public String getLocalNameDisplay() {
            return localName != null ? localName : "<none>";
        }

        public String getRemoteNameDisplay() {
            return remoteName != null ? remoteName : "<none>";
        }
    }

    /**
     * Result of a SymGraph query operation.
     */
    public static class QueryResult {
        private boolean exists;
        private BinaryStats stats;
        private List<BinaryRevision> revisions = new ArrayList<>();
        private Integer latestRevision;
        private Integer selectedRevision;
        private Boolean hasStoredBinary;
        private String error;

        public QueryResult() {}

        public static QueryResult found(BinaryStats stats) {
            QueryResult result = new QueryResult();
            result.exists = true;
            result.stats = stats;
            return result;
        }

        public static QueryResult found(
                BinaryStats stats,
                List<BinaryRevision> revisions,
                Integer latestRevision,
                Integer selectedRevision,
                Boolean hasStoredBinary) {
            QueryResult result = new QueryResult();
            result.exists = true;
            result.stats = stats;
            result.revisions = revisions != null ? revisions : new ArrayList<>();
            result.latestRevision = latestRevision;
            result.selectedRevision = selectedRevision;
            result.hasStoredBinary = hasStoredBinary;
            return result;
        }

        public static QueryResult notFound() {
            QueryResult result = new QueryResult();
            result.exists = false;
            return result;
        }

        public static QueryResult error(String errorMsg) {
            QueryResult result = new QueryResult();
            result.exists = false;
            result.error = errorMsg;
            return result;
        }

        public boolean isExists() { return exists; }
        public void setExists(boolean exists) { this.exists = exists; }
        public BinaryStats getStats() { return stats; }
        public void setStats(BinaryStats stats) { this.stats = stats; }
        public List<BinaryRevision> getRevisions() { return revisions; }
        public void setRevisions(List<BinaryRevision> revisions) { this.revisions = revisions; }
        public Integer getLatestRevision() { return latestRevision; }
        public void setLatestRevision(Integer latestRevision) { this.latestRevision = latestRevision; }
        public Integer getSelectedRevision() { return selectedRevision; }
        public void setSelectedRevision(Integer selectedRevision) { this.selectedRevision = selectedRevision; }
        public Boolean getHasStoredBinary() { return hasStoredBinary; }
        public void setHasStoredBinary(Boolean hasStoredBinary) { this.hasStoredBinary = hasStoredBinary; }
        public String getError() { return error; }
        public void setError(String error) { this.error = error; }
    }

    /**
     * Result of a SymGraph push operation.
     */
    public static class PushResult {
        private boolean success;
        private int symbolsPushed;
        private int nodesPushed;
        private int edgesPushed;
        private int documentsPushed;
        private Integer binaryRevision;
        private List<DocumentPushResult> documentResults;
        private String error;
        private String errorCode;
        private String requestedVisibility;
        private String suggestedVisibility;

        public PushResult() {}

        public static PushResult success(int symbols, int nodes, int edges) {
            return success(symbols, nodes, edges, null);
        }

        public static PushResult success(int symbols, int nodes, int edges, Integer binaryRevision) {
            PushResult result = new PushResult();
            result.success = true;
            result.symbolsPushed = symbols;
            result.nodesPushed = nodes;
            result.edgesPushed = edges;
            result.documentsPushed = 0;
            result.binaryRevision = binaryRevision;
            result.documentResults = new ArrayList<>();
            return result;
        }

        public static PushResult failure(String errorMsg) {
            return failure(errorMsg, null, null, null);
        }

        public static PushResult failure(
                String errorMsg,
                String errorCode,
                String requestedVisibility,
                String suggestedVisibility) {
            PushResult result = new PushResult();
            result.success = false;
            result.error = errorMsg;
            result.errorCode = errorCode;
            result.requestedVisibility = requestedVisibility;
            result.suggestedVisibility = suggestedVisibility;
            return result;
        }

        public boolean isSuccess() { return success; }
        public void setSuccess(boolean success) { this.success = success; }
        public int getSymbolsPushed() { return symbolsPushed; }
        public void setSymbolsPushed(int symbolsPushed) { this.symbolsPushed = symbolsPushed; }
        public int getNodesPushed() { return nodesPushed; }
        public void setNodesPushed(int nodesPushed) { this.nodesPushed = nodesPushed; }
        public int getEdgesPushed() { return edgesPushed; }
        public void setEdgesPushed(int edgesPushed) { this.edgesPushed = edgesPushed; }
        public int getDocumentsPushed() { return documentsPushed; }
        public void setDocumentsPushed(int documentsPushed) { this.documentsPushed = documentsPushed; }
        public Integer getBinaryRevision() { return binaryRevision; }
        public void setBinaryRevision(Integer binaryRevision) { this.binaryRevision = binaryRevision; }
        public List<DocumentPushResult> getDocumentResults() {
            return documentResults != null ? documentResults : new ArrayList<>();
        }
        public void setDocumentResults(List<DocumentPushResult> documentResults) {
            this.documentResults = documentResults;
        }
        public String getError() { return error; }
        public void setError(String error) { this.error = error; }
        public String getErrorCode() { return errorCode; }
        public void setErrorCode(String errorCode) { this.errorCode = errorCode; }
        public String getRequestedVisibility() { return requestedVisibility; }
        public void setRequestedVisibility(String requestedVisibility) { this.requestedVisibility = requestedVisibility; }
        public String getSuggestedVisibility() { return suggestedVisibility; }
        public void setSuggestedVisibility(String suggestedVisibility) { this.suggestedVisibility = suggestedVisibility; }
    }

    /**
     * Result of a pull preview operation.
     */
    public static class PullPreviewResult {
        private boolean success;
        private List<ConflictEntry> conflicts;
        private String error;

        public PullPreviewResult() {
            this.conflicts = new ArrayList<>();
        }

        public static PullPreviewResult success(List<ConflictEntry> conflicts) {
            PullPreviewResult result = new PullPreviewResult();
            result.success = true;
            result.conflicts = conflicts;
            return result;
        }

        public static PullPreviewResult failure(String errorMsg) {
            PullPreviewResult result = new PullPreviewResult();
            result.success = false;
            result.error = errorMsg;
            return result;
        }

        public boolean isSuccess() { return success; }
        public void setSuccess(boolean success) { this.success = success; }
        public List<ConflictEntry> getConflicts() { return conflicts; }
        public void setConflicts(List<ConflictEntry> conflicts) { this.conflicts = conflicts; }
        public String getError() { return error; }
        public void setError(String error) { this.error = error; }
    }
}
