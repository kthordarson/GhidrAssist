package ghidrassist.apiprovider;

import java.lang.reflect.Type;
import java.util.ArrayList;
import java.util.List;

import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;

import ghidra.framework.preferences.Preferences;
import ghidra.util.Msg;

/**
 * Persists API provider configuration blobs in Ghidra preferences.
 */
public final class APIProviderConfigStore {
    private static final Gson GSON = new Gson();
    private static final String PROVIDERS_KEY = "GhidrAssist.APIProviders";

    private APIProviderConfigStore() {
    }

    public static boolean updateProviderKey(String providerName, String keyJson) {
        if (providerName == null || providerName.isBlank()) {
            Msg.warn(APIProviderConfigStore.class, "Cannot persist OAuth credentials: provider name is blank");
            return false;
        }

        try {
            Type listType = new TypeToken<List<APIProviderConfig>>() {}.getType();
            String providersJson = Preferences.getProperty(PROVIDERS_KEY, "[]");
            List<APIProviderConfig> providers = GSON.fromJson(providersJson, listType);
            if (providers == null) {
                providers = new ArrayList<>();
            }

            for (APIProviderConfig provider : providers) {
                if (provider == null) {
                    continue;
                }
                provider.normalizeLegacyDefaults();
                if (!providerName.equals(provider.getName())) {
                    continue;
                }
                if (keyJson.equals(provider.getKey())) {
                    return false;
                }

                provider.setKey(keyJson);
                Preferences.setProperty(PROVIDERS_KEY, GSON.toJson(providers));
                Preferences.store();
                Msg.info(APIProviderConfigStore.class,
                    "Persisted refreshed OAuth credentials for provider: " + providerName);
                return true;
            }

            Msg.warn(APIProviderConfigStore.class,
                "Unable to persist refreshed OAuth credentials: provider not found: " + providerName);
            return false;
        } catch (Exception e) {
            Msg.warn(APIProviderConfigStore.class,
                "Failed to persist refreshed OAuth credentials for provider " + providerName + ": " + e.getMessage());
            return false;
        }
    }
}
