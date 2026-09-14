package ghidrassist.apiprovider;

import ghidrassist.GhidrAssistPlugin;
import ghidrassist.apiprovider.factory.ProviderRegistry;
import ghidrassist.apiprovider.factory.UnsupportedProviderException;

public class APIProviderConfig {
    private static final int DEFAULT_MAX_TOKENS = 16384;
    private static final int DEFAULT_TIMEOUT = 90;
    private static final String OPENAI_OAUTH_RESPONSES_URL = "https://chatgpt.com/backend-api/codex/responses";
    private static final String OPENAI_OAUTH_BASE_URL = "https://chatgpt.com/backend-api/codex";

    private String name;
    private String model;
    private Integer maxTokens;
    private String url;
    private String key;
    private boolean disableTlsVerification;
    private boolean bypassProxy;
    private APIProvider.ProviderType type;
    private Integer timeout;

    public APIProviderConfig(
            String name,
            APIProvider.ProviderType type,
            String model,
            Integer maxTokens,
            String url,
            String key,
            boolean disableTlsVerification) {
        this(name, type, model, maxTokens, url, key, disableTlsVerification, false, 90);
    }

    public APIProviderConfig(
            String name,
            APIProvider.ProviderType type,
            String model,
            Integer maxTokens,
            String url,
            String key,
            boolean disableTlsVerification,
            boolean bypassProxy,
            Integer timeout) {
        this.name = name;
        this.type = type;
        this.model = model;
        this.maxTokens = maxTokens;
        this.url = url;
        this.key = key;
        this.disableTlsVerification = disableTlsVerification;
        this.bypassProxy = bypassProxy;
        this.timeout = timeout != null ? timeout : DEFAULT_TIMEOUT;
    }

    // Getters
    public String getName() { return name; }
    public APIProvider.ProviderType getType() { return type; }
    public String getModel() { return model; }
    public Integer getMaxTokens() { return maxTokens; }
    public String getUrl() { return url; }
    public String getKey() { return key; }
    public boolean isDisableTlsVerification() { return disableTlsVerification; }
    public boolean isBypassProxy() { return bypassProxy; }
    public Integer getTimeout() { return timeout; }

    // Setters
    public void setName(String name) { this.name = name; }
    public void setType(APIProvider.ProviderType type) { this.type = type; }
    public void setModel(String model) { this.model = model; }
    public void setMaxTokens(Integer maxTokens) { this.maxTokens = maxTokens; }
    public void setUrl(String url) { this.url = url; }
    public void setKey(String key) { this.key = key; }
    public void setDisableTlsVerification(boolean disableTlsVerification) { this.disableTlsVerification = disableTlsVerification; }
    public void setBypassProxy(boolean bypassProxy) { this.bypassProxy = bypassProxy; }
    public void setTimeout(Integer timeout) { this.timeout = timeout != null ? timeout : DEFAULT_TIMEOUT; }

    /**
     * Backfill missing fields from older serialized provider configs so they remain loadable.
     */
    public void normalizeLegacyDefaults() {
        if (name == null) {
            name = "";
        }
        if (type == null) {
            type = APIProvider.ProviderType.OPENAI_PLATFORM_API;
        }
        if (model == null) {
            model = "";
        }
        if (maxTokens == null) {
            maxTokens = DEFAULT_MAX_TOKENS;
        }
        if (url == null) {
            url = "";
        }
        if (type == APIProvider.ProviderType.OPENAI_OAUTH) {
            String normalizedUrl = url.trim();
            if (normalizedUrl.isEmpty()
                    || "https://chatgpt.com".equalsIgnoreCase(normalizedUrl)
                    || "https://chatgpt.com/".equalsIgnoreCase(normalizedUrl)
                    || "http://chatgpt.com".equalsIgnoreCase(normalizedUrl)
                    || "http://chatgpt.com/".equalsIgnoreCase(normalizedUrl)
                    || "https://www.chatgpt.com".equalsIgnoreCase(normalizedUrl)
                    || "https://www.chatgpt.com/".equalsIgnoreCase(normalizedUrl)
                    || "http://www.chatgpt.com".equalsIgnoreCase(normalizedUrl)
                    || "http://www.chatgpt.com/".equalsIgnoreCase(normalizedUrl)
                    || OPENAI_OAUTH_BASE_URL.equalsIgnoreCase(normalizedUrl)
                    || (OPENAI_OAUTH_BASE_URL + "/").equalsIgnoreCase(normalizedUrl)
                    || normalizedUrl.endsWith("/models")) {
                url = OPENAI_OAUTH_RESPONSES_URL;
            }
        }
        if (key == null) {
            key = "";
        }
        if (timeout == null) {
            timeout = DEFAULT_TIMEOUT;
        }
    }

    /**
     * Create a provider using the factory pattern
     * @return Configured API provider instance
     * @throws RuntimeException if provider creation fails
     */
    public APIProvider createProvider() {
        try {
            return ProviderRegistry.getInstance().createProvider(this);
        } catch (UnsupportedProviderException e) {
            throw new IllegalArgumentException("Failed to create provider: " + e.getMessage(), e);
        }
    }

    /**
     * Create a copy of this provider
     * @return new provider instance with identical configuration
     */
    public APIProviderConfig copy() {
        return new APIProviderConfig(name, type, model, maxTokens, url, key, disableTlsVerification, bypassProxy, timeout);
    }
    
    /**
     * Check if this provider type is supported
     * @return true if the provider type is supported
     */
    public boolean isSupported() {
        return ProviderRegistry.getInstance().isSupported(type);
    }
}
