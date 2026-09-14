package ghidrassist.apiprovider.factory;

import ghidrassist.apiprovider.APIProvider;
import ghidrassist.apiprovider.APIProviderConfig;
import ghidrassist.apiprovider.XaiPlatformApiProvider;

/**
 * Factory for creating xAI (Grok) API providers.
 */
public class XaiPlatformApiProviderFactory implements APIProviderFactory {

    @Override
    public APIProvider createProvider(APIProviderConfig config) throws UnsupportedProviderException {
        if (!supports(config.getType())) {
            throw new UnsupportedProviderException(config.getType(), getFactoryName());
        }

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
    public boolean supports(APIProvider.ProviderType type) {
        return type == APIProvider.ProviderType.XAI_PLATFORM_API;
    }

    @Override
    public APIProvider.ProviderType getProviderType() {
        return APIProvider.ProviderType.XAI_PLATFORM_API;
    }

    @Override
    public String getFactoryName() {
        return "XaiPlatformApiProviderFactory";
    }
}
