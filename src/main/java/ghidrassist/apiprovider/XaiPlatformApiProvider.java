package ghidrassist.apiprovider;

import ghidrassist.apiprovider.exceptions.APIProviderException;

/**
 * xAI (Grok) Provider - OpenAI-compatible API at https://api.x.ai/v1.
 * Inherits all chat, streaming, function calling, and model listing from OpenAIPlatformApiProvider.
 * xAI does not offer an embeddings endpoint.
 */
public class XaiPlatformApiProvider extends OpenAIPlatformApiProvider {

    public XaiPlatformApiProvider(String name, String model, Integer maxTokens, String url,
                                   String key, boolean disableTlsVerification, boolean bypassProxy, Integer timeout) {
        super(name, model, maxTokens, url, key, disableTlsVerification, bypassProxy, timeout);

        // Override the type to XAI_PLATFORM_API
        this.type = ProviderType.XAI_PLATFORM_API;
    }

    public static XaiPlatformApiProvider fromConfig(APIProviderConfig config) {
        return new XaiPlatformApiProvider(
            config.getName(),
            config.getModel(),
            config.getMaxTokens(),
            config.getUrl(),
            config.getKey(),
            config.isDisableTlsVerification(),
            config.isBypassProxy(),
            config.getTimeout()
        );
    }

    @Override
    public void getEmbeddingsAsync(String text, EmbeddingCallback callback) {
        callback.onError(new APIProviderException(
            APIProviderException.ErrorCategory.CONFIGURATION,
            name, "get_embeddings",
            "xAI does not support embeddings"));
    }
}
