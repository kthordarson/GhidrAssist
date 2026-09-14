package ghidrassist.apiprovider;

import ghidrassist.apiprovider.exceptions.APIProviderException;

/**
 * Google Gemini Provider - OpenAI-compatible API at
 * https://generativelanguage.googleapis.com/v1beta/openai/.
 * Inherits all chat, streaming, function calling, and model listing from OpenAIPlatformApiProvider.
 * Gemini's OpenAI-compatible endpoint does not support embeddings.
 */
public class GeminiPlatformApiProvider extends OpenAIPlatformApiProvider {

    public GeminiPlatformApiProvider(String name, String model, Integer maxTokens, String url,
                                      String key, boolean disableTlsVerification, boolean bypassProxy, Integer timeout) {
        super(name, model, maxTokens, url, key, disableTlsVerification, bypassProxy, timeout);

        // Override the type to GEMINI_PLATFORM_API
        this.type = ProviderType.GEMINI_PLATFORM_API;
    }

    public static GeminiPlatformApiProvider fromConfig(APIProviderConfig config) {
        return new GeminiPlatformApiProvider(
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
            "Gemini OpenAI-compatible endpoint does not support embeddings"));
    }
}
