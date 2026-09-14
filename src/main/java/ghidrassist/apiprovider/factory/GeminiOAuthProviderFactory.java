package ghidrassist.apiprovider.factory;

import ghidrassist.apiprovider.APIProvider;
import ghidrassist.apiprovider.APIProviderConfig;
import ghidrassist.apiprovider.GeminiOAuthProvider;

/**
 * Factory for creating Google Gemini OAuth API providers.
 *
 * This provider uses OAuth authentication for Google Gemini CLI subscriptions,
 * routing requests through the Code Assist proxy endpoint.
 */
public class GeminiOAuthProviderFactory implements APIProviderFactory {

    @Override
    public APIProvider createProvider(APIProviderConfig config) throws UnsupportedProviderException {
        if (!supports(config.getType())) {
            throw new UnsupportedProviderException(config.getType(), getFactoryName());
        }

        return new GeminiOAuthProvider(
            config.getName(),
            config.getModel(),
            config.getMaxTokens(),
            config.getUrl(),
            config.getKey(),  // Contains OAuth credentials as JSON
            config.isDisableTlsVerification(),
            config.isBypassProxy(),
            config.getTimeout()
        );
    }

    @Override
    public boolean supports(APIProvider.ProviderType type) {
        return type == APIProvider.ProviderType.GEMINI_OAUTH;
    }

    @Override
    public APIProvider.ProviderType getProviderType() {
        return APIProvider.ProviderType.GEMINI_OAUTH;
    }

    @Override
    public String getFactoryName() {
        return "GeminiOAuthProviderFactory";
    }
}
