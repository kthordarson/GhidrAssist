package ghidrassist.services.symgraph;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.google.gson.reflect.TypeToken;

import ghidra.framework.preferences.Preferences;
import ghidra.util.Msg;
import ghidrassist.services.symgraph.SymGraphModels.*;
import okhttp3.*;

/**
 * Service for interacting with the SymGraph API.
 * Provides methods for querying, pushing, and pulling symbols and graph data.
 */
public class SymGraphService {
    private static final String TAG = "SymGraphService";
    private static final MediaType JSON = MediaType.parse("application/json; charset=utf-8");
    private static final int TIMEOUT_SECONDS = 120;  // Increased for large uploads
    private static final int CHUNK_SIZE = 500;  // Symbols/nodes per chunk

    // Retry settings for rate limiting (429 responses)
    private static final int MAX_RETRIES = 5;
    private static final long INITIAL_BACKOFF_MS = 1000;  // 1 second
    private static final long MAX_BACKOFF_MS = 30000;     // 30 seconds

    private final Gson gson;
    private OkHttpClient client;

    /**
     * Progress callback interface for chunked operations.
     */
    public interface ProgressCallback {
        void onProgress(int current, int total, String message);
        boolean isCancelled();
    }

    public SymGraphService() {
        // serializeNulls ensures ALL fields are sent, even if null
        this.gson = new GsonBuilder().serializeNulls().create();
        this.client = buildClient();
    }

    /**
     * Rebuild the HTTP client if settings change (e.g., API URL changed).
     */
    public void rebuildClient() {
        this.client = buildClient();
    }

    private OkHttpClient buildClient() {
        OkHttpClient.Builder builder = new OkHttpClient.Builder()
                .connectTimeout(Duration.ofSeconds(30))
                .readTimeout(Duration.ofSeconds(TIMEOUT_SECONDS))
                .writeTimeout(Duration.ofSeconds(TIMEOUT_SECONDS));

        // Allow insecure connections for localhost, private/internal networks, or when user disables TLS
        boolean disableTls = "true".equals(
            Preferences.getProperty("GhidrAssist.SymGraphDisableTls", "false"));
        String apiUrl = getApiUrl();
        if (disableTls
                || apiUrl.contains("localhost") || apiUrl.contains("127.0.0.1")
                || apiUrl.matches(".*://10\\..*") || apiUrl.matches(".*://172\\.(1[6-9]|2[0-9]|3[01])\\..*")
                || apiUrl.matches(".*://192\\.168\\..*")) {
            try {
                // Create a trust manager that does not validate certificate chains
                final javax.net.ssl.TrustManager[] trustAllCerts = new javax.net.ssl.TrustManager[]{
                    new javax.net.ssl.X509TrustManager() {
                        @Override
                        public void checkClientTrusted(java.security.cert.X509Certificate[] chain, String authType) {}
                        @Override
                        public void checkServerTrusted(java.security.cert.X509Certificate[] chain, String authType) {}
                        @Override
                        public java.security.cert.X509Certificate[] getAcceptedIssuers() { return new java.security.cert.X509Certificate[]{}; }
                    }
                };

                // Install the all-trusting trust manager
                final javax.net.ssl.SSLContext sslContext = javax.net.ssl.SSLContext.getInstance("SSL");
                sslContext.init(null, trustAllCerts, new java.security.SecureRandom());
                final javax.net.ssl.SSLSocketFactory sslSocketFactory = sslContext.getSocketFactory();

                builder.sslSocketFactory(sslSocketFactory, (javax.net.ssl.X509TrustManager) trustAllCerts[0]);
                builder.hostnameVerifier((hostname, session) -> true);

                Msg.debug(this, TAG + ": Using insecure SSL for internal network: " + apiUrl);
            } catch (Exception e) {
                Msg.warn(this, TAG + ": Failed to configure insecure SSL: " + e.getMessage());
            }
        }

        return builder.build();
    }

    // === Settings helpers ===

    public String getApiUrl() {
        String url = Preferences.getProperty("GhidrAssist.SymGraphAPIUrl", "https://symgraph.ai");
        return url.endsWith("/") ? url.substring(0, url.length() - 1) : url;
    }

    public String getWebUrl() {
        String apiUrl = getApiUrl();
        try {
            URI uri = new URI(apiUrl);
            String host = uri.getHost();
            String path = uri.getPath() != null ? uri.getPath() : "";

            if (host != null && host.startsWith("api.") && (path.isEmpty() || "/".equals(path))) {
                host = host.substring(4);
            }

            if (path.endsWith("/api/v1")) {
                path = path.substring(0, path.length() - 7);
            } else if (path.endsWith("/api")) {
                path = path.substring(0, path.length() - 4);
            }

            URI webUri = new URI(
                uri.getScheme(),
                uri.getUserInfo(),
                host,
                uri.getPort(),
                path.isEmpty() ? null : path,
                null,
                null
            );
            String normalized = webUri.toString();
            return normalized.endsWith("/") ? normalized.substring(0, normalized.length() - 1) : normalized;
        } catch (URISyntaxException e) {
            Msg.warn(this, TAG + ": Failed to normalize SymGraph web URL: " + e.getMessage());
            return apiUrl;
        }
    }

    public String getBinaryUrl(String sha256) {
        return getWebUrl() + "/binaries/" + sha256;
    }

    public String getApiKey() {
        return Preferences.getProperty("GhidrAssist.SymGraphAPIKey", "");
    }

    public boolean hasApiKey() {
        String key = getApiKey();
        return key != null && !key.trim().isEmpty();
    }

    // === Unauthenticated Operations ===

    /**
     * Check if a binary exists in SymGraph (unauthenticated).
     */
    public boolean checkBinaryExists(String sha256) throws IOException {
        String url = getApiUrl() + "/api/v1/binaries/" + sha256;
        Msg.debug(this, TAG + ": Checking binary existence: " + url);

        Request request = new Request.Builder()
                .url(url)
                .head()
                .addHeader("Accept", "application/json")
                .addHeader("User-Agent", "GhidrAssist-SymGraph/1.0")
                .build();

        try (Response response = client.newCall(request).execute()) {
            return response.isSuccessful();
        }
    }

    /**
     * Get binary statistics from SymGraph (unauthenticated).
     */
    public BinaryStats getBinaryStats(String sha256) throws IOException {
        return getBinaryStats(sha256, null);
    }

    public BinaryStats getBinaryStats(String sha256, Integer version) throws IOException {
        HttpUrl.Builder urlBuilder = HttpUrl.parse(getApiUrl() + "/api/v1/binaries/" + sha256 + "/stats").newBuilder();
        if (version != null) {
            urlBuilder.addQueryParameter("version", String.valueOf(version));
        }
        String url = urlBuilder.build().toString();
        Msg.debug(this, TAG + ": Getting binary stats: " + url);

        Request.Builder requestBuilder = new Request.Builder()
                .url(url)
                .get()
                .addHeader("Accept", "application/json")
                .addHeader("User-Agent", "GhidrAssist-SymGraph/1.0");
        if (hasApiKey()) {
            requestBuilder.addHeader("X-API-Key", getApiKey());
        }
        Request request = requestBuilder.build();

        try (Response response = client.newCall(request).execute()) {
            if (!response.isSuccessful()) {
                if (response.code() == 404) {
                    return null;
                }
                throw new IOException("Unexpected response: " + response.code());
            }

            String body = response.body().string();
            JsonObject json = JsonParser.parseString(body).getAsJsonObject();

            // Stats may be nested inside a "stats" object
            JsonObject statsJson = json.has("stats") && json.get("stats").isJsonObject()
                    ? json.getAsJsonObject("stats")
                    : json;

            BinaryStats stats = new BinaryStats();
            stats.setSymbolCount(getIntOrDefault(statsJson, "symbol_count", 0));
            stats.setFunctionCount(getIntOrDefault(statsJson, "function_count", 0));
            stats.setGraphNodeCount(getIntOrDefault(statsJson, "graph_node_count", 0));
            stats.setGraphEdgeCount(getIntOrDefault(statsJson, "graph_edge_count", 0));
            stats.setQueryCount(getIntOrDefault(statsJson, "query_count", 0));
            // last_queried_at might be at top level even when stats are nested
            String lastQueried = getStringOrNull(json, "last_queried_at");
            if (lastQueried == null) {
                lastQueried = getStringOrNull(statsJson, "last_queried_at");
            }
            stats.setLastQueriedAt(lastQueried);

            return stats;
        }
    }

    public Boolean getStoredBinaryFlag(String sha256) throws IOException, SymGraphAuthException {
        checkAuthRequired();

        String url = getApiUrl() + "/api/v1/binaries/" + sha256;
        Msg.debug(this, TAG + ": Getting binary info: " + url);

        Request request = new Request.Builder()
                .url(url)
                .get()
                .addHeader("Accept", "application/json")
                .addHeader("X-API-Key", getApiKey())
                .addHeader("User-Agent", "GhidrAssist-SymGraph/1.0")
                .build();

        try (Response response = client.newCall(request).execute()) {
            if (response.code() == 401) {
                throw new SymGraphAuthException("Invalid API key");
            }
            if (response.code() == 404) {
                return Boolean.FALSE;
            }
            if (!response.isSuccessful()) {
                throw new IOException("Unexpected response: " + response.code());
            }

            String body = response.body().string();
            JsonObject json = JsonParser.parseString(body).getAsJsonObject();
            if (json.has("has_stored_binary") && !json.get("has_stored_binary").isJsonNull()) {
                return json.get("has_stored_binary").getAsBoolean();
            }
            if (json.has("binary") && json.get("binary").isJsonObject()) {
                JsonObject binaryJson = json.getAsJsonObject("binary");
                if (binaryJson.has("has_stored_binary") && !binaryJson.get("has_stored_binary").isJsonNull()) {
                    return binaryJson.get("has_stored_binary").getAsBoolean();
                }
            }
            return null;
        }
    }

    public BinaryUploadResult uploadBinary(String fileName, byte[] fileBytes)
            throws IOException, SymGraphAuthException {
        checkAuthRequired();

        String uploadName = (fileName == null || fileName.isBlank()) ? "binary.bin" : fileName;
        String url = getApiUrl() + "/api/v1/analysis/upload";
        Msg.debug(this, TAG + ": Uploading raw binary: " + uploadName + " (" + fileBytes.length + " bytes)");

        RequestBody fileBody = RequestBody.create(fileBytes, MediaType.parse("application/octet-stream"));
        RequestBody body = new MultipartBody.Builder()
                .setType(MultipartBody.FORM)
                .addFormDataPart("file", uploadName, fileBody)
                .build();

        Request request = new Request.Builder()
                .url(url)
                .post(body)
                .addHeader("Accept", "application/json")
                .addHeader("X-API-Key", getApiKey())
                .addHeader("User-Agent", "GhidrAssist-SymGraph/1.0")
                .build();

        try (Response response = client.newCall(request).execute()) {
            if (response.code() == 401) {
                throw new SymGraphAuthException("Invalid API key");
            }
            if (!response.isSuccessful()) {
                throw buildApiIOException("Error uploading binary", response);
            }

            String responseBody = response.body().string();
            JsonObject json = JsonParser.parseString(responseBody).getAsJsonObject();
            BinaryUploadResult result = new BinaryUploadResult();
            result.setSha256(getStringOrNull(json, "sha256"));
            result.setBinaryId(getStringOrNull(json, "binary_id"));
            result.setFileSize(getLongOrDefault(json, "file_size", 0));
            result.setNew(json.has("is_new") && !json.get("is_new").isJsonNull() && json.get("is_new").getAsBoolean());
            result.setMessage(getStringOrNull(json, "message"));
            result.setMetadataExtracted(json.has("metadata_extracted")
                    && !json.get("metadata_extracted").isJsonNull()
                    && json.get("metadata_extracted").getAsBoolean());
            return result;
        }
    }

    /**
     * List accessible binary revisions (authenticated).
     */
    public List<BinaryRevision> listBinaryVersions(String sha256) throws IOException, SymGraphAuthException {
        checkAuthRequired();

        String url = getApiUrl() + "/api/v1/binaries/" + sha256 + "/versions";
        Msg.debug(this, TAG + ": Listing binary versions: " + url);

        Request request = new Request.Builder()
                .url(url)
                .get()
                .addHeader("Accept", "application/json")
                .addHeader("X-API-Key", getApiKey())
                .addHeader("User-Agent", "GhidrAssist-SymGraph/1.0")
                .build();

        try (Response response = client.newCall(request).execute()) {
            if (response.code() == 401) {
                throw new SymGraphAuthException("Invalid API key");
            }
            if (response.code() == 404) {
                return new ArrayList<>();
            }
            if (!response.isSuccessful()) {
                throw buildApiIOException("Error listing binary versions", response);
            }

            String body = response.body().string();
            JsonObject json = JsonParser.parseString(body).getAsJsonObject();
            List<BinaryRevision> revisions = new ArrayList<>();
            if (json.has("revisions") && json.get("revisions").isJsonArray()) {
                JsonArray revisionsArray = json.getAsJsonArray("revisions");
                for (JsonElement element : revisionsArray) {
                    if (!element.isJsonObject()) {
                        continue;
                    }
                    JsonObject revObj = element.getAsJsonObject();
                    BinaryRevision revision = new BinaryRevision();
                    revision.setVersion(getIntOrDefault(revObj, "version", 0));
                    revision.setCreatedAt(getStringOrNull(revObj, "created_at"));
                    revision.setVisibility(getStringOrNull(revObj, "visibility"));
                    revision.setLatest(revObj.has("is_latest") && !revObj.get("is_latest").isJsonNull()
                            && revObj.get("is_latest").getAsBoolean());
                    revision.setOwnerUsername(getStringOrNull(revObj, "owner_username"));
                    revisions.add(revision);
                }
            }
            return revisions;
        }
    }

    /**
     * Query SymGraph for binary info (unauthenticated).
     */
    public QueryResult queryBinary(String sha256) {
        return queryBinary(sha256, null, false);
    }

    public QueryResult queryBinary(String sha256, Integer version, boolean includeVersions) {
        try {
            boolean exists = checkBinaryExists(sha256);
            if (!exists) {
                return QueryResult.notFound();
            }

            List<BinaryRevision> revisions = new ArrayList<>();
            Integer latestRevision = null;
            Boolean hasStoredBinary = null;
            if (hasApiKey()) {
                try {
                    hasStoredBinary = getStoredBinaryFlag(sha256);
                } catch (Exception e) {
                    Msg.warn(this, TAG + ": Unable to fetch binary storage state: " + e.getMessage());
                }
            }
            if (includeVersions && hasApiKey()) {
                try {
                    revisions = listBinaryVersions(sha256);
                    if (!revisions.isEmpty()) {
                        latestRevision = revisions.get(0).getVersion();
                    }
                } catch (Exception e) {
                    Msg.warn(this, TAG + ": Unable to list binary versions: " + e.getMessage());
                }
            }

            Integer effectiveVersion = version != null ? version : latestRevision;
            BinaryStats stats = getBinaryStats(sha256, effectiveVersion);
            if (stats == null && effectiveVersion != null) {
                Msg.warn(this, TAG + ": No stats returned for version " + effectiveVersion +
                        ", retrying without an explicit version");
                stats = getBinaryStats(sha256, null);
            }
            return QueryResult.found(stats, revisions, latestRevision, effectiveVersion, hasStoredBinary);
        } catch (Exception e) {
            Msg.error(this, TAG + ": Query error: " + e.getMessage());
            return QueryResult.error(e.getMessage());
        }
    }

    /**
     * Query SymGraph asynchronously.
     */
    public CompletableFuture<QueryResult> queryBinaryAsync(String sha256) {
        return CompletableFuture.supplyAsync(() -> queryBinary(sha256));
    }

    // === Authenticated Operations ===

    /**
     * Get symbols for a binary (authenticated).
     * @param sha256 SHA256 hash of the binary
     * @param symbolType Optional symbol type filter (e.g., "function", "data", "type"). Pass null for all symbols.
     */
    public List<Symbol> getSymbols(String sha256, String symbolType) throws IOException, SymGraphAuthException {
        return getSymbols(sha256, symbolType, null);
    }

    public List<Symbol> getSymbols(String sha256, String symbolType, Integer version) throws IOException, SymGraphAuthException {
        checkAuthRequired();

        HttpUrl.Builder urlBuilder = HttpUrl.parse(getApiUrl() + "/api/v1/binaries/" + sha256 + "/symbols").newBuilder();
        if (symbolType != null && !symbolType.isEmpty()) {
            urlBuilder.addQueryParameter("type", symbolType);
        }
        if (version != null) {
            urlBuilder.addQueryParameter("version", String.valueOf(version));
        }
        String url = urlBuilder.build().toString();
        Msg.debug(this, TAG + ": Getting symbols: " + url);

        Request request = new Request.Builder()
                .url(url)
                .get()
                .addHeader("Accept", "application/json")
                .addHeader("X-API-Key", getApiKey())
                .addHeader("User-Agent", "GhidrAssist-SymGraph/1.0")
                .build();

        try (Response response = client.newCall(request).execute()) {
            if (response.code() == 401) {
                throw new SymGraphAuthException("Invalid API key");
            }
            if (response.code() == 404) {
                return new ArrayList<>();
            }
            if (!response.isSuccessful()) {
                throw buildApiIOException("Error getting symbols", response);
            }

            String body = response.body().string();
            JsonObject json = JsonParser.parseString(body).getAsJsonObject();

            // Handle null or missing symbols safely
            JsonArray symbolsArray = null;
            if (json.has("symbols") && !json.get("symbols").isJsonNull()) {
                symbolsArray = json.getAsJsonArray("symbols");
            } else {
                // Try parsing body as array directly
                JsonElement bodyElement = JsonParser.parseString(body);
                if (bodyElement.isJsonArray()) {
                    symbolsArray = bodyElement.getAsJsonArray();
                }
            }

            // Return empty list if no valid symbols array
            if (symbolsArray == null) {
                return new ArrayList<>();
            }

            List<Symbol> symbols = new ArrayList<>();
            for (JsonElement elem : symbolsArray) {
                JsonObject symObj = elem.getAsJsonObject();
                Symbol symbol = new Symbol();
                symbol.setAddress(getLongOrDefault(symObj, "address", 0));
                symbol.setSymbolType(getStringOrDefault(symObj, "symbol_type", "function"));
                symbol.setName(getStringOrNull(symObj, "name"));
                symbol.setDataType(getStringOrNull(symObj, "data_type"));
                symbol.setConfidence(getDoubleOrDefault(symObj, "confidence", 0.0));
                symbol.setProvenance(getStringOrDefault(symObj, "provenance", "unknown"));
                symbol.setContent(getStringOrNull(symObj, "content"));

                // Parse metadata if present (for variables, comments, structs, enums)
                if (symObj.has("metadata") && !symObj.get("metadata").isJsonNull()) {
                    Map<String, Object> metadata = gson.fromJson(
                            symObj.get("metadata"), new TypeToken<Map<String, Object>>() {}.getType());
                    symbol.setMetadata(metadata);
                }

                symbols.add(symbol);
            }

            return symbols;
        }
    }

    /**
     * Export graph data for a binary (authenticated).
     */
    public GraphExport exportGraph(String sha256) throws IOException, SymGraphAuthException {
        return exportGraph(sha256, null);
    }

    public GraphExport exportGraph(String sha256, Integer version) throws IOException, SymGraphAuthException {
        checkAuthRequired();

        HttpUrl.Builder urlBuilder = HttpUrl.parse(getApiUrl() + "/api/v1/binaries/" + sha256 + "/graph/export").newBuilder();
        if (version != null) {
            urlBuilder.addQueryParameter("version", String.valueOf(version));
        }
        String url = urlBuilder.build().toString();
        Msg.debug(this, TAG + ": Exporting graph: " + url);

        Request request = new Request.Builder()
                .url(url)
                .get()
                .addHeader("Accept", "application/json")
                .addHeader("X-API-Key", getApiKey())
                .addHeader("User-Agent", "GhidrAssist-SymGraph/1.0")
                .build();

        try (Response response = client.newCall(request).execute()) {
            if (response.code() == 401) {
                throw new SymGraphAuthException("Invalid API key");
            }
            if (response.code() == 404) {
                return null;
            }
            if (!response.isSuccessful()) {
                throw new IOException("Error exporting graph: " + response.code());
            }

            String body = response.body().string();
            JsonObject json = JsonParser.parseString(body).getAsJsonObject();

            GraphExport export = new GraphExport();
            export.setBinarySha256(getStringOrDefault(json, "binary_sha256", sha256));
            export.setExportVersion(getStringOrDefault(json, "export_version", "1.0"));

            if (json.has("metadata") && json.get("metadata").isJsonObject()) {
                Map<String, Object> metadata = gson.fromJson(
                        json.get("metadata"), new TypeToken<Map<String, Object>>() {}.getType());
                export.setMetadata(metadata);
            }

            List<GraphNode> nodes = new ArrayList<>();
            if (json.has("nodes") && json.get("nodes").isJsonArray()) {
                JsonArray nodesArray = json.getAsJsonArray("nodes");
                for (JsonElement elem : nodesArray) {
                    JsonObject nodeObj = elem.getAsJsonObject();
                    GraphNode node = new GraphNode();
                    node.setId(getStringOrNull(nodeObj, "id"));
                    node.setAddress(getLongOrDefault(nodeObj, "address", 0));
                    node.setNodeType(getStringOrDefault(nodeObj, "node_type", "function"));
                    node.setName(getStringOrNull(nodeObj, "name"));
                    node.setSummary(getStringOrNull(nodeObj, "llm_summary"));

                    // Build properties map from top-level fields AND nested properties
                    // Backend sends RE analysis fields at the top level, not nested in "properties"
                    Map<String, Object> props = new HashMap<>();

                    // First, copy any nested properties object
                    if (nodeObj.has("properties") && nodeObj.get("properties").isJsonObject()) {
                        Map<String, Object> nestedProps = gson.fromJson(
                                nodeObj.get("properties"), new TypeToken<Map<String, Object>>() {}.getType());
                        props.putAll(nestedProps);
                    }

                    // Then parse top-level RE analysis fields (these override nested if present)
                    if (nodeObj.has("signature") && !nodeObj.get("signature").isJsonNull()) {
                        props.put("signature", nodeObj.get("signature").getAsString());
                    }
                    if (nodeObj.has("decompiled_code") && !nodeObj.get("decompiled_code").isJsonNull()) {
                        props.put("decompiled_code", nodeObj.get("decompiled_code").getAsString());
                    }
                    if (nodeObj.has("disassembly") && !nodeObj.get("disassembly").isJsonNull()) {
                        props.put("disassembly", nodeObj.get("disassembly").getAsString());
                    }
                    if (nodeObj.has("raw_content") && !nodeObj.get("raw_content").isJsonNull()) {
                        props.put("raw_content", nodeObj.get("raw_content").getAsString());
                    }
                    if (!props.containsKey("decompiled_code") && props.containsKey("raw_content")) {
                        props.put("decompiled_code", props.get("raw_content"));
                    }
                    if (nodeObj.has("confidence") && !nodeObj.get("confidence").isJsonNull()) {
                        props.put("confidence", nodeObj.get("confidence").getAsDouble());
                    }
                    if (nodeObj.has("security_flags") && !nodeObj.get("security_flags").isJsonNull()) {
                        props.put("security_flags", gson.fromJson(nodeObj.get("security_flags"),
                                new TypeToken<List<String>>() {}.getType()));
                    }
                    if (nodeObj.has("network_apis") && !nodeObj.get("network_apis").isJsonNull()) {
                        props.put("network_apis", gson.fromJson(nodeObj.get("network_apis"),
                                new TypeToken<List<String>>() {}.getType()));
                    }
                    if (nodeObj.has("file_io_apis") && !nodeObj.get("file_io_apis").isJsonNull()) {
                        props.put("file_io_apis", gson.fromJson(nodeObj.get("file_io_apis"),
                                new TypeToken<List<String>>() {}.getType()));
                    }
                    if (nodeObj.has("ip_addresses") && !nodeObj.get("ip_addresses").isJsonNull()) {
                        props.put("ip_addresses", gson.fromJson(nodeObj.get("ip_addresses"),
                                new TypeToken<List<String>>() {}.getType()));
                    }
                    if (nodeObj.has("urls") && !nodeObj.get("urls").isJsonNull()) {
                        props.put("urls", gson.fromJson(nodeObj.get("urls"),
                                new TypeToken<List<String>>() {}.getType()));
                    }
                    if (nodeObj.has("file_paths") && !nodeObj.get("file_paths").isJsonNull()) {
                        props.put("file_paths", gson.fromJson(nodeObj.get("file_paths"),
                                new TypeToken<List<String>>() {}.getType()));
                    }
                    if (nodeObj.has("domains") && !nodeObj.get("domains").isJsonNull()) {
                        props.put("domains", gson.fromJson(nodeObj.get("domains"),
                                new TypeToken<List<String>>() {}.getType()));
                    }
                    if (nodeObj.has("registry_keys") && !nodeObj.get("registry_keys").isJsonNull()) {
                        props.put("registry_keys", gson.fromJson(nodeObj.get("registry_keys"),
                                new TypeToken<List<String>>() {}.getType()));
                    }
                    if (nodeObj.has("risk_level") && !nodeObj.get("risk_level").isJsonNull()) {
                        props.put("risk_level", nodeObj.get("risk_level").getAsString());
                    }
                    if (nodeObj.has("category") && !nodeObj.get("category").isJsonNull()) {
                        props.put("category", nodeObj.get("category").getAsString());
                    }
                    if (nodeObj.has("activity_profile") && !nodeObj.get("activity_profile").isJsonNull()) {
                        props.put("activity_profile", nodeObj.get("activity_profile").getAsString());
                    }
                    if (nodeObj.has("analysis_depth") && !nodeObj.get("analysis_depth").isJsonNull()) {
                        props.put("analysis_depth", nodeObj.get("analysis_depth").getAsInt());
                    }

                    node.setProperties(props);
                    nodes.add(node);
                }
            }
            export.setNodes(nodes);

            List<GraphEdge> edges = new ArrayList<>();
            if (json.has("edges") && json.get("edges").isJsonArray()) {
                JsonArray edgesArray = json.getAsJsonArray("edges");
                for (JsonElement elem : edgesArray) {
                    JsonObject edgeObj = elem.getAsJsonObject();
                    GraphEdge edge = new GraphEdge();
                    edge.setSourceAddress(getLongOrDefault(edgeObj, "source_address", 0));
                    edge.setTargetAddress(getLongOrDefault(edgeObj, "target_address", 0));
                    edge.setSourceName(getStringOrDefault(edgeObj, "source_name", null));
                    edge.setTargetName(getStringOrDefault(edgeObj, "target_name", null));
                    edge.setEdgeType(getStringOrDefault(edgeObj, "edge_type", "calls"));
                    if (edgeObj.has("properties") && edgeObj.get("properties").isJsonObject()) {
                        Map<String, Object> props = gson.fromJson(
                                edgeObj.get("properties"), new TypeToken<Map<String, Object>>() {}.getType());
                        edge.setProperties(props);
                    }
                    edges.add(edge);
                }
            }
            export.setEdges(edges);

            return export;
        }
    }

    /**
     * List documents for a binary (authenticated).
     */
    public List<DocumentSummary> listDocuments(String sha256, Integer version) throws IOException, SymGraphAuthException {
        checkAuthRequired();

        HttpUrl.Builder urlBuilder = HttpUrl.parse(getApiUrl() + "/api/v1/binaries/" + sha256 + "/documents").newBuilder();
        urlBuilder.addQueryParameter("page_size", "100");
        if (version != null) {
            urlBuilder.addQueryParameter("version", String.valueOf(version));
        }
        String url = urlBuilder.build().toString();
        Msg.debug(this, TAG + ": Listing documents: " + url);

        Request request = new Request.Builder()
                .url(url)
                .get()
                .addHeader("Accept", "application/json")
                .addHeader("X-API-Key", getApiKey())
                .addHeader("User-Agent", "GhidrAssist-SymGraph/1.0")
                .build();

        try (Response response = client.newCall(request).execute()) {
            if (response.code() == 401) {
                throw new SymGraphAuthException("Invalid API key");
            }
            if (response.code() == 404) {
                return new ArrayList<>();
            }
            if (!response.isSuccessful()) {
                throw buildApiIOException("Error listing documents", response);
            }

            String body = response.body().string();
            JsonObject json = JsonParser.parseString(body).getAsJsonObject();
            List<DocumentSummary> documents = new ArrayList<>();
            if (!json.has("documents") || !json.get("documents").isJsonArray()) {
                return documents;
            }

            for (JsonElement element : json.getAsJsonArray("documents")) {
                if (!element.isJsonObject()) {
                    continue;
                }
                documents.add(parseDocumentSummary(element.getAsJsonObject()));
            }
            return documents;
        }
    }

    /**
     * Get a single document with content (authenticated).
     */
    public Document getDocument(String sha256, String documentIdentityId, Integer version)
            throws IOException, SymGraphAuthException {
        checkAuthRequired();

        HttpUrl.Builder urlBuilder = HttpUrl.parse(
                getApiUrl() + "/api/v1/binaries/" + sha256 + "/documents/" + documentIdentityId).newBuilder();
        if (version != null) {
            urlBuilder.addQueryParameter("version", String.valueOf(version));
        }
        String url = urlBuilder.build().toString();
        Msg.debug(this, TAG + ": Getting document: " + url);

        Request request = new Request.Builder()
                .url(url)
                .get()
                .addHeader("Accept", "application/json")
                .addHeader("X-API-Key", getApiKey())
                .addHeader("User-Agent", "GhidrAssist-SymGraph/1.0")
                .build();

        try (Response response = client.newCall(request).execute()) {
            if (response.code() == 401) {
                throw new SymGraphAuthException("Invalid API key");
            }
            if (response.code() == 404) {
                return null;
            }
            if (!response.isSuccessful()) {
                throw buildApiIOException("Error getting document", response);
            }

            String body = response.body().string();
            JsonObject json = JsonParser.parseString(body).getAsJsonObject();
            return parseDocument(json);
        }
    }

    /**
     * Push documents in bulk (authenticated).
     */
    public PushResult pushDocumentsBulk(
            String sha256,
            List<Map<String, Object>> documents,
            Integer baseVersion,
            ProgressCallback progress) throws IOException, SymGraphAuthException {
        checkAuthRequired();

        if (documents == null || documents.isEmpty()) {
            return PushResult.success(0, 0, 0, baseVersion);
        }
        if (progress != null && progress.isCancelled()) {
            return PushResult.success(0, 0, 0, baseVersion);
        }

        HttpUrl.Builder urlBuilder = HttpUrl.parse(getApiUrl() + "/api/v1/binaries/" + sha256 + "/documents/bulk").newBuilder();
        if (baseVersion != null) {
            urlBuilder.addQueryParameter("base_version", String.valueOf(baseVersion));
        }
        HttpUrl url = urlBuilder.build();
        Msg.debug(this, TAG + ": Pushing " + documents.size() + " documents to: " + url);

        Map<String, Object> payload = new HashMap<>();
        payload.put("documents", documents);

        RequestBody body = RequestBody.create(gson.toJson(payload), JSON);
        Request request = new Request.Builder()
                .url(url)
                .post(body)
                .addHeader("Content-Type", "application/json")
                .addHeader("Accept", "application/json")
                .addHeader("X-API-Key", getApiKey())
                .addHeader("User-Agent", "GhidrAssist-SymGraph/1.0")
                .build();

        try (Response response = executeWithRetry(request, progress)) {
            if (response.code() == 401) {
                throw new SymGraphAuthException("Invalid API key");
            }
            if (!response.isSuccessful()) {
                return buildPushFailure("Error pushing documents", response);
            }

            String responseBody = response.body().string();
            JsonObject json = JsonParser.parseString(responseBody).getAsJsonObject();
            List<DocumentPushResult> results = new ArrayList<>();
            int pushed = 0;

            if (json.has("results") && json.get("results").isJsonArray()) {
                for (JsonElement element : json.getAsJsonArray("results")) {
                    if (!element.isJsonObject()) {
                        continue;
                    }
                    JsonObject resultObj = element.getAsJsonObject();
                    DocumentPushResult result = new DocumentPushResult();
                    result.setStatus(getStringOrNull(resultObj, "status"));
                    result.setDocumentIdentityId(getStringOrNull(resultObj, "document_identity_id"));
                    result.setVersion(getIntOrDefault(resultObj, "version", 0));
                    result.setMessage(getStringOrNull(resultObj, "message"));
                    if (resultObj.has("document") && resultObj.get("document").isJsonObject()) {
                        result.setDocument(parseDocument(resultObj.getAsJsonObject("document")));
                    }
                    if (result.getDocument() != null
                            || "created".equals(result.getStatus())
                            || "versioned".equals(result.getStatus())
                            || "skipped".equals(result.getStatus())) {
                        pushed++;
                    }
                    results.add(result);
                }
            }

            PushResult pushResult = PushResult.success(0, 0, 0, baseVersion);
            pushResult.setDocumentsPushed(pushed);
            pushResult.setDocumentResults(results);
            return pushResult;
        }
    }

    /**
     * Push symbols to SymGraph in bulk (authenticated).
     */
    public PushResult pushSymbolsBulk(String sha256, List<Map<String, Object>> symbols) throws IOException, SymGraphAuthException {
        return pushSymbolsBulk(sha256, symbols, null, null);
    }

    /**
     * Push symbols to SymGraph in bulk with retry support (authenticated).
     */
    public PushResult pushSymbolsBulk(String sha256, List<Map<String, Object>> symbols, ProgressCallback progress) throws IOException, SymGraphAuthException {
        return pushSymbolsBulk(sha256, symbols, null, progress);
    }

    public PushResult pushSymbolsBulk(
            String sha256,
            List<Map<String, Object>> symbols,
            Integer targetRevision,
            ProgressCallback progress) throws IOException, SymGraphAuthException {
        checkAuthRequired();

        HttpUrl.Builder urlBuilder = HttpUrl.parse(getApiUrl() + "/api/v1/binaries/" + sha256 + "/symbols/bulk").newBuilder();
        if (targetRevision != null) {
            urlBuilder.addQueryParameter("target_revision", String.valueOf(targetRevision));
        }
        HttpUrl url = urlBuilder.build();
        Msg.debug(this, TAG + ": Pushing " + symbols.size() + " symbols to: " + url);

        Map<String, Object> payload = new HashMap<>();
        payload.put("symbols", symbols);

        RequestBody body = RequestBody.create(gson.toJson(payload), JSON);

        Request request = new Request.Builder()
                .url(url)
                .post(body)
                .addHeader("Content-Type", "application/json")
                .addHeader("Accept", "application/json")
                .addHeader("X-API-Key", getApiKey())
                .addHeader("User-Agent", "GhidrAssist-SymGraph/1.0")
                .build();

        try (Response response = executeWithRetry(request, progress)) {
            if (response.code() == 401) {
                throw new SymGraphAuthException("Invalid API key");
            }
            if (!response.isSuccessful()) {
                return buildPushFailure("Error pushing symbols", response);
            }

            String responseBody = response.body().string();
            JsonObject json = JsonParser.parseString(responseBody).getAsJsonObject();
            int symbolsCreated = getIntOrDefault(json, "symbols_created", symbols.size());
            Integer binaryRevision = json.has("binary_revision") && !json.get("binary_revision").isJsonNull()
                    ? json.get("binary_revision").getAsInt()
                    : targetRevision;

            return PushResult.success(symbolsCreated, 0, 0, binaryRevision);
        }
    }

    /**
     * Push symbols in chunks with progress reporting (authenticated).
     * Breaks large symbol sets into smaller chunks to avoid timeouts.
     */
    public PushResult pushSymbolsChunked(String sha256, List<Map<String, Object>> symbols, ProgressCallback progress)
            throws IOException, SymGraphAuthException {
        return pushSymbolsChunked(sha256, symbols, null, progress);
    }

    public PushResult pushSymbolsChunked(
            String sha256,
            List<Map<String, Object>> symbols,
            Integer targetRevision,
            ProgressCallback progress) throws IOException, SymGraphAuthException {
        checkAuthRequired();

        if (symbols.isEmpty()) {
            return PushResult.success(0, 0, 0);
        }

        int totalSymbols = symbols.size();
        int totalPushed = 0;
        int chunkIndex = 0;
        Integer writeRevision = targetRevision;

        if (writeRevision == null) {
            PushResult revisionResult = createBinaryRevision(sha256, "public");
            if (!revisionResult.isSuccess()) {
                return revisionResult;
            }
            writeRevision = revisionResult.getBinaryRevision();
        }

        Msg.info(this, TAG + ": Pushing " + totalSymbols + " symbols in chunks of " + CHUNK_SIZE);

        for (int i = 0; i < totalSymbols; i += CHUNK_SIZE) {
            // Check for cancellation
            if (progress != null && progress.isCancelled()) {
                Msg.info(this, TAG + ": Push cancelled by user");
                return PushResult.success(totalPushed, 0, 0);
            }

            int end = Math.min(i + CHUNK_SIZE, totalSymbols);
            List<Map<String, Object>> chunk = symbols.subList(i, end);
            chunkIndex++;

            // Report progress
            if (progress != null) {
                progress.onProgress(i, totalSymbols,
                        String.format("Pushing symbols... %d/%d (chunk %d)", i, totalSymbols, chunkIndex));
            }

            // Push this chunk (with retry support)
            PushResult chunkResult = pushSymbolsBulk(sha256, chunk, writeRevision, progress);
            if (!chunkResult.isSuccess()) {
                return PushResult.failure("Chunk " + chunkIndex + " failed: " + chunkResult.getError());
            }

            totalPushed += chunkResult.getSymbolsPushed();
        }

        // Final progress update
        if (progress != null) {
            progress.onProgress(totalSymbols, totalSymbols, "Symbols complete");
        }

        Msg.info(this, TAG + ": Successfully pushed " + totalPushed + " symbols");
        return PushResult.success(totalPushed, 0, 0, writeRevision);
    }

    /**
     * Import graph data in chunks with progress reporting (authenticated).
     * Splits nodes and edges into manageable chunks.
     */
    @SuppressWarnings("unchecked")
    public PushResult importGraphChunked(String sha256, Map<String, Object> graphData, ProgressCallback progress)
            throws IOException, SymGraphAuthException {
        return importGraphChunked(sha256, graphData, null, progress);
    }

    @SuppressWarnings("unchecked")
    public PushResult importGraphChunked(
            String sha256,
            Map<String, Object> graphData,
            Integer targetRevision,
            ProgressCallback progress) throws IOException, SymGraphAuthException {
        checkAuthRequired();

        List<Map<String, Object>> nodes = (List<Map<String, Object>>) graphData.get("nodes");
        List<Map<String, Object>> edges = (List<Map<String, Object>>) graphData.get("edges");

        if ((nodes == null || nodes.isEmpty()) && (edges == null || edges.isEmpty())) {
            return PushResult.success(0, 0, 0);
        }

        int totalNodes = nodes != null ? nodes.size() : 0;
        int totalEdges = edges != null ? edges.size() : 0;
        int totalItems = totalNodes + totalEdges;
        int processedItems = 0;
        int totalNodesPushed = 0;
        int totalEdgesPushed = 0;
        Integer writeRevision = targetRevision;

        if (writeRevision == null) {
            PushResult revisionResult = createBinaryRevision(sha256, "public");
            if (!revisionResult.isSuccess()) {
                return revisionResult;
            }
            writeRevision = revisionResult.getBinaryRevision();
        }

        Msg.info(this, TAG + ": Pushing " + totalNodes + " nodes and " + totalEdges + " edges");

        // Push nodes in chunks
        if (nodes != null && !nodes.isEmpty()) {
            for (int i = 0; i < totalNodes; i += CHUNK_SIZE) {
                if (progress != null && progress.isCancelled()) {
                    Msg.info(this, TAG + ": Push cancelled by user");
                    return PushResult.success(0, totalNodesPushed, totalEdgesPushed);
                }

                int end = Math.min(i + CHUNK_SIZE, totalNodes);
                List<Map<String, Object>> nodeChunk = nodes.subList(i, end);

                if (progress != null) {
                    progress.onProgress(processedItems, totalItems,
                            String.format("Pushing nodes... %d/%d", i, totalNodes));
                }

                Map<String, Object> chunkData = new HashMap<>();
                chunkData.put("nodes", nodeChunk);
                chunkData.put("edges", new ArrayList<>());

                PushResult result = importGraph(sha256, chunkData, writeRevision, progress);
                if (!result.isSuccess()) {
                    return PushResult.failure("Node chunk failed: " + result.getError());
                }

                totalNodesPushed += result.getNodesPushed();
                processedItems += nodeChunk.size();
            }
        }

        // Push edges in chunks
        if (edges != null && !edges.isEmpty()) {
            for (int i = 0; i < totalEdges; i += CHUNK_SIZE) {
                if (progress != null && progress.isCancelled()) {
                    Msg.info(this, TAG + ": Push cancelled by user");
                    return PushResult.success(0, totalNodesPushed, totalEdgesPushed);
                }

                int end = Math.min(i + CHUNK_SIZE, totalEdges);
                List<Map<String, Object>> edgeChunk = edges.subList(i, end);

                if (progress != null) {
                    progress.onProgress(processedItems, totalItems,
                            String.format("Pushing edges... %d/%d", i, totalEdges));
                }

                Map<String, Object> chunkData = new HashMap<>();
                chunkData.put("nodes", new ArrayList<>());
                chunkData.put("edges", edgeChunk);

                PushResult result = importGraph(sha256, chunkData, writeRevision, progress);
                if (!result.isSuccess()) {
                    return PushResult.failure("Edge chunk failed: " + result.getError());
                }

                totalEdgesPushed += result.getEdgesPushed();
                processedItems += edgeChunk.size();
            }
        }

        // Final progress update
        if (progress != null) {
            progress.onProgress(totalItems, totalItems, "Graph complete");
        }

        Msg.info(this, TAG + ": Successfully pushed " + totalNodesPushed + " nodes, " + totalEdgesPushed + " edges");
        return PushResult.success(0, totalNodesPushed, totalEdgesPushed, writeRevision);
    }

    /**
     * Import graph data to SymGraph (authenticated).
     */
    public PushResult importGraph(String sha256, Map<String, Object> graphData) throws IOException, SymGraphAuthException {
        return importGraph(sha256, graphData, null, null);
    }

    /**
     * Import graph data to SymGraph with retry support (authenticated).
     */
    public PushResult importGraph(String sha256, Map<String, Object> graphData, ProgressCallback progress) throws IOException, SymGraphAuthException {
        return importGraph(sha256, graphData, null, progress);
    }

    public PushResult importGraph(
            String sha256,
            Map<String, Object> graphData,
            Integer targetRevision,
            ProgressCallback progress) throws IOException, SymGraphAuthException {
        checkAuthRequired();

        HttpUrl.Builder urlBuilder = HttpUrl.parse(getApiUrl() + "/api/v1/binaries/" + sha256 + "/graph/import").newBuilder();
        if (targetRevision != null) {
            urlBuilder.addQueryParameter("target_revision", String.valueOf(targetRevision));
        }
        HttpUrl url = urlBuilder.build();
        Msg.debug(this, TAG + ": Importing graph to: " + url);

        RequestBody body = RequestBody.create(gson.toJson(buildGraphExportPayload(sha256, graphData)), JSON);

        Request request = new Request.Builder()
                .url(url)
                .post(body)
                .addHeader("Content-Type", "application/json")
                .addHeader("Accept", "application/json")
                .addHeader("X-API-Key", getApiKey())
                .addHeader("User-Agent", "GhidrAssist-SymGraph/1.0")
                .build();

        try (Response response = executeWithRetry(request, progress)) {
            if (response.code() == 401) {
                throw new SymGraphAuthException("Invalid API key");
            }
            if (!response.isSuccessful()) {
                return buildPushFailure("Error importing graph", response);
            }

            String responseBody = response.body().string();
            JsonObject json = JsonParser.parseString(responseBody).getAsJsonObject();
            int nodesImported = getIntOrDefault(json, "nodes_imported", getIntOrDefault(json, "imported_nodes", 0));
            int edgesImported = getIntOrDefault(json, "edges_imported", getIntOrDefault(json, "imported_edges", 0));
            Integer binaryRevision = json.has("binary_revision") && !json.get("binary_revision").isJsonNull()
                    ? json.get("binary_revision").getAsInt()
                    : targetRevision;

            return PushResult.success(0, nodesImported, edgesImported, binaryRevision);
        }
    }

    public PushResult createBinaryRevision(String sha256, String visibility) throws IOException, SymGraphAuthException {
        checkAuthRequired();

        String url = getApiUrl() + "/api/v1/binaries/" + sha256 + "/versions";
        Msg.debug(this, TAG + ": Creating binary revision at: " + url + " visibility=" + visibility);

        Map<String, Object> payload = new HashMap<>();
        payload.put("visibility", visibility);

        RequestBody body = RequestBody.create(gson.toJson(payload), JSON);

        Request request = new Request.Builder()
                .url(url)
                .post(body)
                .addHeader("Content-Type", "application/json")
                .addHeader("Accept", "application/json")
                .addHeader("X-API-Key", getApiKey())
                .addHeader("User-Agent", "GhidrAssist-SymGraph/1.0")
                .build();

        try (Response response = client.newCall(request).execute()) {
            if (response.code() == 401) {
                throw new SymGraphAuthException("Invalid API key");
            }
            if (!response.isSuccessful()) {
                return buildPushFailure("Error creating binary revision", response);
            }

            String responseBody = response.body().string();
            JsonObject json = JsonParser.parseString(responseBody).getAsJsonObject();
            int binaryRevision = getIntOrDefault(json, "version", 0);
            return PushResult.success(0, 0, 0, binaryRevision);
        }
    }

    public PushResult updateBinaryMetadata(String sha256, Map<String, Object> metadata)
            throws IOException, SymGraphAuthException {
        checkAuthRequired();

        if (metadata == null || metadata.isEmpty()) {
            return PushResult.success(0, 0, 0);
        }

        String url = getApiUrl() + "/api/v1/binaries/" + sha256;
        Msg.debug(this, TAG + ": Updating binary metadata keys=" + metadata.keySet());

        RequestBody body = RequestBody.create(gson.toJson(metadata), JSON);

        Request request = new Request.Builder()
                .url(url)
                .patch(body)
                .addHeader("Content-Type", "application/json")
                .addHeader("Accept", "application/json")
                .addHeader("X-API-Key", getApiKey())
                .addHeader("User-Agent", "GhidrAssist-SymGraph/1.0")
                .build();

        try (Response response = client.newCall(request).execute()) {
            if (response.code() == 401) {
                throw new SymGraphAuthException("Invalid API key");
            }
            if (!response.isSuccessful()) {
                return buildPushFailure("Error updating binary metadata", response);
            }
            return PushResult.success(0, 0, 0);
        }
    }

    /**
     * Add a fingerprint to a binary (authenticated).
     * Used for debug symbol matching (BuildID for ELF, PDB GUID for PE).
     */
    public boolean addFingerprint(String sha256, String fpType, String fpValue) throws IOException, SymGraphAuthException {
        checkAuthRequired();

        String url = getApiUrl() + "/api/v1/binaries/" + sha256 + "/fingerprints";
        Msg.debug(this, TAG + ": Adding fingerprint " + fpType + "=" + fpValue);

        JsonObject payload = new JsonObject();
        payload.addProperty("type", fpType);
        payload.addProperty("value", fpValue);

        RequestBody body = RequestBody.create(
                payload.toString(),
                MediaType.parse("application/json")
        );

        Request request = new Request.Builder()
                .url(url)
                .post(body)
                .addHeader("Accept", "application/json")
                .addHeader("X-API-Key", getApiKey())
                .addHeader("User-Agent", "GhidrAssist-SymGraph/1.0")
                .build();

        try (Response response = client.newCall(request).execute()) {
            if (response.code() == 401) {
                throw new SymGraphAuthException("Invalid API key");
            }
            if (response.code() == 409) {
                // Fingerprint already exists - not an error
                Msg.debug(this, TAG + ": Fingerprint already exists");
                return true;
            }
            if (!response.isSuccessful()) {
                Msg.warn(this, TAG + ": Failed to add fingerprint: " + response.code());
                return false;
            }
            Msg.info(this, TAG + ": Added fingerprint: " + fpType + "=" + fpValue);
            return true;
        }
    }

    /**
     * Get all symbols for a binary (authenticated).
     * Convenience overload that fetches all symbol types.
     */
    public List<Symbol> getSymbols(String sha256) throws IOException, SymGraphAuthException {
        return getSymbols(sha256, null);
    }

    /**
     * Get symbols asynchronously.
     */
    public CompletableFuture<List<Symbol>> getSymbolsAsync(String sha256) {
        return getSymbolsAsync(sha256, null);
    }

    /**
     * Get symbols asynchronously with optional type filter.
     * @param sha256 SHA256 hash of the binary
     * @param symbolType Optional symbol type filter (e.g., "function"). Pass null for all symbols.
     */
    public CompletableFuture<List<Symbol>> getSymbolsAsync(String sha256, String symbolType) {
        return CompletableFuture.supplyAsync(() -> {
            try {
                return getSymbols(sha256, symbolType);
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        });
    }

    /**
     * Push symbols asynchronously.
     */
    public CompletableFuture<PushResult> pushSymbolsBulkAsync(String sha256, List<Map<String, Object>> symbols) {
        return CompletableFuture.supplyAsync(() -> {
            try {
                return pushSymbolsBulk(sha256, symbols);
            } catch (Exception e) {
                return PushResult.failure(e.getMessage());
            }
        });
    }

    private PushResult buildPushFailure(String prefix, Response response) throws IOException {
        String errorBody = response.body() != null ? response.body().string() : "";
        String message = prefix + ": HTTP " + response.code();
        String errorCode = null;
        String requestedVisibility = null;
        String suggestedVisibility = null;

        if (errorBody != null && !errorBody.isEmpty()) {
            try {
                JsonElement errorElement = JsonParser.parseString(errorBody);
                if (errorElement.isJsonObject()) {
                    JsonObject errorJson = errorElement.getAsJsonObject();
                    String apiMessage = getStringOrNull(errorJson, "error");
                    if (apiMessage != null && !apiMessage.isEmpty()) {
                        message = prefix + ": " + apiMessage;
                    } else {
                        message = prefix + ": HTTP " + response.code();
                    }
                    errorCode = getStringOrNull(errorJson, "code");
                    requestedVisibility = getStringOrNull(errorJson, "requested_visibility");
                    suggestedVisibility = getStringOrNull(errorJson, "suggested_visibility");
                } else {
                    message = prefix + ": " + errorBody;
                }
            } catch (Exception parseError) {
                message = prefix + ": " + errorBody;
            }
        }

        return PushResult.failure(message, errorCode, requestedVisibility, suggestedVisibility);
    }

    private IOException buildApiIOException(String prefix, Response response) throws IOException {
        String errorBody = response.body() != null ? response.body().string() : "";
        String message = prefix + ": HTTP " + response.code();
        if (errorBody != null && !errorBody.isEmpty()) {
            try {
                JsonElement errorElement = JsonParser.parseString(errorBody);
                if (errorElement.isJsonObject()) {
                    JsonObject errorJson = errorElement.getAsJsonObject();
                    String apiMessage = getStringOrNull(errorJson, "error");
                    if (apiMessage != null && !apiMessage.isEmpty()) {
                        message = prefix + ": " + apiMessage;
                    }
                } else {
                    message = prefix + ": " + errorBody;
                }
            } catch (Exception parseError) {
                message = prefix + ": " + errorBody;
            }
        }
        return new IOException(message);
    }

    private Map<String, Object> buildGraphExportPayload(String sha256, Map<String, Object> graphData) {
        Map<String, Object> payload = new HashMap<>();
        payload.put("version", graphData.getOrDefault("version", graphData.getOrDefault("export_version", "1.0")));
        payload.put("exported_at", Instant.now().toString());

        Map<String, Object> binary = new HashMap<>();
        binary.put("sha256", sha256);
        payload.put("binary", binary);
        payload.put("nodes", graphData.getOrDefault("nodes", new ArrayList<>()));
        payload.put("edges", graphData.getOrDefault("edges", new ArrayList<>()));
        payload.put("communities", graphData.getOrDefault("communities", new ArrayList<>()));
        payload.put("community_members", graphData.getOrDefault("community_members", new ArrayList<>()));

        return payload;
    }

    // === Helper Methods ===

    /**
     * Build conflict entries by comparing local and remote symbols.
     * Filters out remote symbols with default/auto-generated names and applies confidence threshold.
     *
     * @param localSymbols Map of address to local symbol name
     * @param remoteSymbols List of remote symbols from the server
     * @param minConfidence Minimum confidence threshold (0.0-1.0) for remote symbols
     * @return List of conflict entries for the merge UI
     */
    public List<ConflictEntry> buildConflictEntries(Map<Long, String> localSymbols, List<Symbol> remoteSymbols, double minConfidence) {
        List<ConflictEntry> conflicts = new ArrayList<>();
        int skippedDefault = 0;
        int skippedConfidence = 0;
        int skippedDuplicate = 0;

        // Deduplicate by address: keep the best symbol per address.
        // Prefer named symbols (function/variable) over comments,
        // and higher confidence over lower.
        Map<Long, Symbol> bestByAddress = new java.util.LinkedHashMap<>();
        for (Symbol remoteSym : remoteSymbols) {
            String displayName = remoteSym.getDisplayName();
            boolean isComment = "comment".equals(remoteSym.getSymbolType());

            // Skip symbols with no useful display name (null name AND null content)
            if (displayName == null || displayName.isEmpty()) {
                skippedDefault++;
                continue;
            }

            // Skip non-comment symbols with default/auto-generated names
            if (!isComment && SymGraphUtils.isDefaultName(remoteSym.getName())) {
                skippedDefault++;
                continue;
            }

            // Skip remote symbols below minimum confidence threshold
            if (remoteSym.getConfidence() < minConfidence) {
                skippedConfidence++;
                continue;
            }

            long addr = remoteSym.getAddress();
            Symbol existing = bestByAddress.get(addr);
            if (existing == null) {
                bestByAddress.put(addr, remoteSym);
            } else {
                // Prefer non-comment over comment, then higher confidence
                boolean existingIsComment = "comment".equals(existing.getSymbolType());
                if (existingIsComment && !isComment) {
                    bestByAddress.put(addr, remoteSym);
                    skippedDuplicate++;
                } else if (!existingIsComment && isComment) {
                    skippedDuplicate++;
                } else if (remoteSym.getConfidence() > existing.getConfidence()) {
                    bestByAddress.put(addr, remoteSym);
                    skippedDuplicate++;
                } else {
                    skippedDuplicate++;
                }
            }
        }

        for (Symbol remoteSym : bestByAddress.values()) {
            long addr = remoteSym.getAddress();
            String localName = localSymbols.get(addr);
            boolean localIsDefault = SymGraphUtils.isDefaultName(localName);

            if (localName == null || localIsDefault) {
                // Remote only OR local has default name - NEW (safe to apply)
                conflicts.add(ConflictEntry.createNew(addr, remoteSym));
            } else if (localName.equals(remoteSym.getDisplayName())) {
                // Same value - SAME
                conflicts.add(ConflictEntry.createSame(addr, localName, remoteSym));
            } else {
                // Different values (both user-defined) - CONFLICT
                conflicts.add(ConflictEntry.createConflict(addr, localName, remoteSym));
            }
        }

        if (skippedDefault > 0 || skippedConfidence > 0 || skippedDuplicate > 0) {
            Msg.info(this, String.format("Filtered out %d default names, %d low confidence, %d duplicates",
                    skippedDefault, skippedConfidence, skippedDuplicate));
        }

        return conflicts;
    }

    /**
     * Build conflict entries with default minimum confidence of 0.0.
     */
    public List<ConflictEntry> buildConflictEntries(Map<Long, String> localSymbols, List<Symbol> remoteSymbols) {
        return buildConflictEntries(localSymbols, remoteSymbols, 0.0);
    }

    private void checkAuthRequired() throws SymGraphAuthException {
        if (!hasApiKey()) {
            throw new SymGraphAuthException("SymGraph.ai API key not configured. Add your API key in Settings > General > SymGraph");
        }
    }

    /**
     * Execute an HTTP request with retry logic for rate limiting (429) responses.
     * Uses exponential backoff with jitter.
     *
     * @param request The request to execute
     * @param progress Optional progress callback to report retry status
     * @return The successful response
     * @throws IOException If the request fails after all retries
     */
    @SuppressWarnings("unused")  // lastException preserved for debugging/future use
    private Response executeWithRetry(Request request, ProgressCallback progress) throws IOException {
        int attempt = 0;
        long backoffMs = INITIAL_BACKOFF_MS;
        IOException lastException = null;

        while (attempt < MAX_RETRIES) {
            attempt++;

            Response response;
            try {
                response = client.newCall(request).execute();
            } catch (IOException e) {
                // Network error - log and retry
                Msg.warn(this, TAG + ": Network error on attempt " + attempt + ": " + e.getMessage());
                lastException = e;
                if (attempt >= MAX_RETRIES) {
                    throw new IOException("Network error after " + MAX_RETRIES + " retries: " + e.getMessage(), e);
                }
                // Use backoff for network errors too
                sleepWithBackoff(backoffMs, attempt, progress, "Network error");
                backoffMs = Math.min(backoffMs * 2, MAX_BACKOFF_MS);
                continue;
            }

            if (response.code() != 429) {
                // Not rate limited, return the response
                return response;
            }

            // Read Retry-After header BEFORE closing the response
            String retryAfter = response.header("Retry-After");

            // Close the 429 response body
            response.close();

            if (attempt >= MAX_RETRIES) {
                throw new IOException("Rate limited (429) after " + MAX_RETRIES + " retries. Please try again later.");
            }

            // Check for cancellation before sleeping
            if (progress != null && progress.isCancelled()) {
                throw new IOException("Cancelled during rate limit backoff");
            }

            // Calculate wait time from Retry-After header or use exponential backoff
            long waitMs = backoffMs;
            if (retryAfter != null) {
                try {
                    waitMs = Long.parseLong(retryAfter) * 1000;
                } catch (NumberFormatException e) {
                    // Use default backoff
                }
            }

            // Add jitter (±20%)
            long jitter = (long) (waitMs * 0.2 * (Math.random() - 0.5));
            waitMs = Math.min(waitMs + jitter, MAX_BACKOFF_MS);

            Msg.info(this, TAG + ": Rate limited (429), waiting " + waitMs + "ms before retry " + attempt + "/" + MAX_RETRIES);

            // Update progress to show we're waiting
            if (progress != null) {
                final long finalWaitMs = waitMs;
                final int finalAttempt = attempt;
                progress.onProgress(-1, -1, String.format("Rate limited, retrying in %.1fs (%d/%d)...",
                        finalWaitMs / 1000.0, finalAttempt, MAX_RETRIES));
            }

            try {
                Thread.sleep(waitMs);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new IOException("Interrupted during rate limit backoff");
            }

            // Exponential backoff for next attempt
            backoffMs = Math.min(backoffMs * 2, MAX_BACKOFF_MS);
        }

        // Should never reach here due to throws in loop, but just in case
        throw new IOException("Failed after " + MAX_RETRIES + " attempts");
    }

    /**
     * Sleep with backoff, updating progress and checking for cancellation.
     */
    private void sleepWithBackoff(long backoffMs, int attempt, ProgressCallback progress, String reason) throws IOException {
        // Add jitter (±20%)
        long jitter = (long) (backoffMs * 0.2 * (Math.random() - 0.5));
        long waitMs = Math.min(backoffMs + jitter, MAX_BACKOFF_MS);

        Msg.info(this, TAG + ": " + reason + ", waiting " + waitMs + "ms before retry " + attempt + "/" + MAX_RETRIES);

        // Update progress to show we're waiting
        if (progress != null) {
            progress.onProgress(-1, -1, String.format("%s, retrying in %.1fs (%d/%d)...",
                    reason, waitMs / 1000.0, attempt, MAX_RETRIES));
        }

        // Check for cancellation before sleeping
        if (progress != null && progress.isCancelled()) {
            throw new IOException("Cancelled during backoff");
        }

        try {
            Thread.sleep(waitMs);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IOException("Interrupted during backoff");
        }
    }

    private DocumentSummary parseDocumentSummary(JsonObject obj) {
        DocumentSummary document = new DocumentSummary();
        document.setId(getStringOrNull(obj, "id"));
        document.setDocumentIdentityId(getStringOrNull(obj, "document_identity_id"));
        document.setVersion(getIntOrDefault(obj, "version", 0));
        document.setTitle(getStringOrNull(obj, "title"));
        document.setDocType(getStringOrNull(obj, "doc_type"));
        document.setContentSizeBytes(getIntOrDefault(obj, "content_size_bytes", 0));
        document.setCreatedAt(getStringOrNull(obj, "created_at"));
        return document;
    }

    private Document parseDocument(JsonObject obj) {
        Document document = new Document();
        document.setId(getStringOrNull(obj, "id"));
        document.setDocumentIdentityId(getStringOrNull(obj, "document_identity_id"));
        document.setVersion(getIntOrDefault(obj, "version", 0));
        document.setTitle(getStringOrNull(obj, "title"));
        document.setDocType(getStringOrNull(obj, "doc_type"));
        document.setContentSizeBytes(getIntOrDefault(obj, "content_size_bytes", 0));
        document.setCreatedAt(getStringOrNull(obj, "created_at"));
        document.setContent(getStringOrNull(obj, "content"));
        return document;
    }

    // JSON helper methods
    private int getIntOrDefault(JsonObject obj, String key, int defaultValue) {
        return obj.has(key) && !obj.get(key).isJsonNull() ? obj.get(key).getAsInt() : defaultValue;
    }

    private long getLongOrDefault(JsonObject obj, String key, long defaultValue) {
        if (!obj.has(key) || obj.get(key).isJsonNull()) {
            return defaultValue;
        }
        try {
            return obj.get(key).getAsLong();
        } catch (NumberFormatException e) {
            try {
                String value = obj.get(key).getAsString();
                if (value != null && value.startsWith("0x")) {
                    return Long.parseLong(value.substring(2), 16);
                }
                return Long.parseLong(value);
            } catch (Exception ignored) {
                return defaultValue;
            }
        }
    }

    private double getDoubleOrDefault(JsonObject obj, String key, double defaultValue) {
        return obj.has(key) && !obj.get(key).isJsonNull() ? obj.get(key).getAsDouble() : defaultValue;
    }

    private String getStringOrNull(JsonObject obj, String key) {
        return obj.has(key) && !obj.get(key).isJsonNull() ? obj.get(key).getAsString() : null;
    }

    private String getStringOrDefault(JsonObject obj, String key, String defaultValue) {
        return obj.has(key) && !obj.get(key).isJsonNull() ? obj.get(key).getAsString() : defaultValue;
    }

    /**
     * Exception for authentication errors.
     */
    public static class SymGraphAuthException extends Exception {
        private static final long serialVersionUID = 1L;

        public SymGraphAuthException(String message) {
            super(message);
        }
    }
}
