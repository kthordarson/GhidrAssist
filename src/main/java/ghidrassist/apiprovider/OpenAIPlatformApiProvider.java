package ghidrassist.apiprovider;

import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.google.gson.JsonSyntaxException;
import com.google.gson.stream.JsonReader;

import ghidrassist.LlmApi;
import ghidrassist.apiprovider.exceptions.*;
import ghidrassist.apiprovider.capabilities.FunctionCallingProvider;
import ghidrassist.apiprovider.capabilities.ModelListProvider;
import ghidrassist.apiprovider.capabilities.EmbeddingProvider;
import okhttp3.*;
import okio.BufferedSource;
import javax.net.ssl.*;
import java.io.IOException;
import java.io.StringReader;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

public class OpenAIPlatformApiProvider extends APIProvider implements FunctionCallingProvider, ModelListProvider, EmbeddingProvider {
    private static final Gson gson = new Gson();
    private static final MediaType JSON = MediaType.get("application/json; charset=utf-8");
    private static final String OPENAI_CHAT_ENDPOINT = "chat/completions";
    private static final String OPENAI_MODELS_ENDPOINT = "models";
    private static final String OPENAI_EMBEDDINGS_ENDPOINT = "embeddings";
    private static final String OPENAI_EMBEDDING_MODEL = "text-embedding-ada-002";

    // Retry settings for streaming calls
    private static final int MAX_STREAMING_RETRIES = 10;
    private static final int MIN_RETRY_BACKOFF_MS = 10000;  // 10 seconds
    private static final int MAX_RETRY_BACKOFF_MS = 30000;  // 30 seconds

    private volatile boolean isCancelled = false;

    public OpenAIPlatformApiProvider(String name, String model, Integer maxTokens, String url, String key,
                                     boolean disableTlsVerification, boolean bypassProxy, Integer timeout) {
        super(name, ProviderType.OPENAI_PLATFORM_API, model, maxTokens, url, key, disableTlsVerification, bypassProxy, timeout);
    }

    public static OpenAIPlatformApiProvider fromConfig(APIProviderConfig config) {
        return new OpenAIPlatformApiProvider(
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
    protected OkHttpClient buildClient() {
        try {
            OkHttpClient.Builder builder = configureClientBuilder(new OkHttpClient.Builder())
                .connectTimeout(super.timeout)
                .readTimeout(super.timeout)
                .writeTimeout(super.timeout)
                .retryOnConnectionFailure(true)
                .addInterceptor(chain -> {
                    Request originalRequest = chain.request();
                    Request.Builder requestBuilder = originalRequest.newBuilder()
                        .header("Authorization", "Bearer " + key)
                        .header("Content-Type", "application/json");
                    
                    if (!originalRequest.method().equals("GET")) {
                        requestBuilder.header("Accept", "application/json");
                    }
                    
                    return chain.proceed(requestBuilder.build());
                });

            if (disableTlsVerification) {
                TrustManager[] trustAllCerts = new TrustManager[]{
                    new X509TrustManager() {
                        @Override
                        public void checkClientTrusted(java.security.cert.X509Certificate[] chain, String authType) {}
                        @Override
                        public void checkServerTrusted(java.security.cert.X509Certificate[] chain, String authType) {}
                        @Override
                        public java.security.cert.X509Certificate[] getAcceptedIssuers() {
                            return new java.security.cert.X509Certificate[]{};
                        }
                    }
                };

                SSLContext sslContext = SSLContext.getInstance("TLS");
                sslContext.init(null, trustAllCerts, new java.security.SecureRandom());
                builder.sslSocketFactory(sslContext.getSocketFactory(), (X509TrustManager) trustAllCerts[0])
                       .hostnameVerifier((hostname, session) -> true);
            }

            return builder.build();
        } catch (Exception e) {
            throw new RuntimeException("Failed to build OpenAI HTTP client: " + e.getMessage(), e);
        }
    }

    @Override
    public String createChatCompletion(List<ChatMessage> messages) throws APIProviderException {
        JsonObject payload = buildChatCompletionPayload(messages, false);
        
        Request request = new Request.Builder()
            .url(url + OPENAI_CHAT_ENDPOINT)
            .post(RequestBody.create(gson.toJson(payload), JSON))
            .build();

        try (Response response = executeWithRetry(request, "createChatCompletion")) {
            String responseBody = response.body().string();
            try {
                JsonObject responseObj = gson.fromJson(responseBody, JsonObject.class);
                return extractContentFromResponse(responseObj);
            } catch (JsonSyntaxException e) {
                throw new ResponseException(name, "createChatCompletion", 
                    ResponseException.ResponseErrorType.MALFORMED_JSON, e);
            }
        } catch (IOException e) {
            throw handleNetworkError(e, "createChatCompletion");
        }
    }

    @Override
    public void streamChatCompletion(List<ChatMessage> messages, LlmApi.LlmResponseHandler handler) throws APIProviderException {
        JsonObject payload = buildChatCompletionPayload(messages, true);
        executeStreamingWithRetry(payload, handler, "stream_chat_completion", 0);
    }

    /**
     * Execute streaming request with retry logic for rate limits and transient errors.
     */
    private void executeStreamingWithRetry(JsonObject payload, LlmApi.LlmResponseHandler handler,
                                           String operation, int attemptNumber) {
        if (isCancelled) {
            handler.onError(new StreamCancelledException(name, operation,
                StreamCancelledException.CancellationReason.USER_REQUESTED));
            return;
        }

        Request request = new Request.Builder()
            .url(url + OPENAI_CHAT_ENDPOINT)
            .post(RequestBody.create(gson.toJson(payload), JSON))
            .build();

        client.newCall(request).enqueue(new Callback() {
            private boolean isFirst = true;

            @Override
            public void onFailure(Call call, IOException e) {
                if (call.isCanceled()) {
                    handler.onError(new StreamCancelledException(name, operation,
                        StreamCancelledException.CancellationReason.USER_REQUESTED, e));
                    return;
                }

                APIProviderException error = handleNetworkError(e, operation);
                if (shouldRetryStreaming(error, attemptNumber)) {
                    retryStreamingAfterDelay(payload, handler, operation, attemptNumber, error);
                } else {
                    handler.onError(error);
                }
            }

            @Override
            public void onResponse(Call call, Response response) throws IOException {
                try (ResponseBody responseBody = response.body()) {
                    if (!response.isSuccessful()) {
                        APIProviderException error = handleHttpError(response, operation);
                        if (shouldRetryStreaming(error, attemptNumber)) {
                            retryStreamingAfterDelay(payload, handler, operation, attemptNumber, error);
                        } else {
                            handler.onError(error);
                        }
                        return;
                    }

                    if (responseBody == null) {
                        handler.onError(new ResponseException(name, operation,
                            ResponseException.ResponseErrorType.EMPTY_RESPONSE));
                        return;
                    }

                    BufferedSource source = responseBody.source();
                    StringBuilder contentBuilder = new StringBuilder();

                    try {
                        while (!source.exhausted() && !isCancelled && handler.shouldContinue()) {
                            String line = source.readUtf8Line();
                            if (line == null || line.isEmpty()) continue;

                            if (line.startsWith("data: ")) {
                                String data = line.substring(6).trim();
                                if (data.equals("[DONE]")) {
                                    handler.onComplete(contentBuilder.toString());
                                    return;
                                }

                                try {
                                    JsonObject chunk = gson.fromJson(data, JsonObject.class);
                                    String content = extractDeltaContent(chunk);

                                    if (content != null) {
                                        if (isFirst) {
                                            handler.onStart();
                                            isFirst = false;
                                        }
                                        contentBuilder.append(content);
                                        handler.onUpdate(content);
                                    }
                                } catch (JsonSyntaxException e) {
                                    handler.onError(new ResponseException(name, operation,
                                        ResponseException.ResponseErrorType.MALFORMED_JSON, e));
                                    return;
                                }
                            }
                        }

                        if (isCancelled) {
                            handler.onError(new StreamCancelledException(name, operation,
                                StreamCancelledException.CancellationReason.USER_REQUESTED));
                        } else if (!handler.shouldContinue()) {
                            handler.onError(new StreamCancelledException(name, operation,
                                StreamCancelledException.CancellationReason.USER_REQUESTED));
                        }
                    } catch (IOException e) {
                        handler.onError(new ResponseException(name, operation,
                            ResponseException.ResponseErrorType.STREAM_INTERRUPTED, e));
                    }
                }
            }
        });
    }

    /**
     * Check if a streaming error should be retried.
     */
    private boolean shouldRetryStreaming(APIProviderException error, int attemptNumber) {
        if (attemptNumber >= MAX_STREAMING_RETRIES) {
            return false;
        }
        switch (error.getCategory()) {
            case RATE_LIMIT:
            case NETWORK:
            case TIMEOUT:
            case SERVICE_ERROR:
                return true;
            default:
                return false;
        }
    }

    /**
     * Retry streaming request after appropriate delay.
     */
    private void retryStreamingAfterDelay(JsonObject payload, LlmApi.LlmResponseHandler handler,
                                          String operation, int attemptNumber, APIProviderException error) {
        int nextAttempt = attemptNumber + 1;
        int waitTimeMs = calculateStreamingRetryWait(error);

        ghidra.util.Msg.warn(this, String.format("Streaming retry %d/%d for %s: %s. Waiting %d seconds...",
            nextAttempt, MAX_STREAMING_RETRIES, operation,
            error.getCategory().getDisplayName(), waitTimeMs / 1000));

        new Thread(() -> {
            try {
                Thread.sleep(waitTimeMs);
                if (!isCancelled) {
                    executeStreamingWithRetry(payload, handler, operation, nextAttempt);
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                handler.onError(new StreamCancelledException(name, operation,
                    StreamCancelledException.CancellationReason.USER_REQUESTED));
            }
        }, "OpenAIPlatformApiProvider-StreamRetry").start();
    }

    /**
     * Calculate wait time for streaming retry with jitter.
     */
    private int calculateStreamingRetryWait(APIProviderException error) {
        if (error.getCategory() == APIProviderException.ErrorCategory.RATE_LIMIT) {
            Integer retryAfter = error.getRetryAfterSeconds();
            if (retryAfter != null && retryAfter > 0) {
                return retryAfter * 1000;
            }
        }
        return MIN_RETRY_BACKOFF_MS + (int) (Math.random() * (MAX_RETRY_BACKOFF_MS - MIN_RETRY_BACKOFF_MS));
    }

    @Override
    public String createChatCompletionWithFunctionsFullResponse(List<ChatMessage> messages, List<Map<String, Object>> functions) throws APIProviderException {
        return createChatCompletionWithFunctionsFullResponse(messages, functions, ToolChoiceMode.AUTO);
    }

    @Override
    public String createChatCompletionWithFunctionsFullResponse(List<ChatMessage> messages,
                                                                List<Map<String, Object>> functions,
                                                                ToolChoiceMode toolChoiceMode) throws APIProviderException {
        JsonObject payload = buildChatCompletionPayload(messages, false);
        
        // Add tools (functions) to the payload
        payload.add("tools", gson.toJsonTree(functions));
        payload.addProperty("tool_choice",
            (toolChoiceMode != null ? toolChoiceMode : ToolChoiceMode.AUTO).toOpenAIToolChoice(messages));
        
        Request request = new Request.Builder()
            .url(url + OPENAI_CHAT_ENDPOINT)
            .post(RequestBody.create(gson.toJson(payload), JSON))
            .build();

        try (Response response = executeWithRetry(request, "createChatCompletionWithFunctionsFullResponse")) {
            String responseBody = response.body().string();
            
            // Return the full response body as-is, including finish_reason
            return responseBody;
            
        } catch (IOException e) {
            throw new NetworkException(name, "createChatCompletionWithFunctionsFullResponse", NetworkException.NetworkErrorType.CONNECTION_FAILED);
        }
    }

    @Override
    public String createChatCompletionWithFunctions(List<ChatMessage> messages, List<Map<String, Object>> functions) throws APIProviderException {
        return createChatCompletionWithFunctions(messages, functions, ToolChoiceMode.AUTO);
    }

    @Override
    public String createChatCompletionWithFunctions(List<ChatMessage> messages, List<Map<String, Object>> functions,
                                                    ToolChoiceMode toolChoiceMode) throws APIProviderException {
        JsonObject payload = buildChatCompletionPayload(messages, false);
        
        // Add tools (functions) to the payload
        payload.add("tools", gson.toJsonTree(functions));
        payload.addProperty("tool_choice",
            (toolChoiceMode != null ? toolChoiceMode : ToolChoiceMode.AUTO).toOpenAIToolChoice(messages));

        Request request = new Request.Builder()
            .url(url + OPENAI_CHAT_ENDPOINT)
            .post(RequestBody.create(gson.toJson(payload), JSON))
            .build();

        try (Response response = executeWithRetry(request, "createChatCompletionWithFunctions")) {
            String responseBody = response.body().string();
            StringReader responseStr = new StringReader(responseBody.replaceFirst("```json", "").replaceAll("```", ""));
            
            try {
                // Create a lenient JsonReader
                JsonReader jsonReader = new JsonReader(responseStr);
                jsonReader.setLenient(true);

                // Parse with lenient reader
                JsonObject responseObj = JsonParser.parseReader(jsonReader).getAsJsonObject();
            JsonObject message = new JsonObject();
            if ( responseObj.has("message") ) {
            	message = responseObj.getAsJsonObject("message");
            } else if ( responseObj.has("choices") ) {
            	JsonArray choices = responseObj.getAsJsonArray("choices");
            	message = choices.get(0).getAsJsonObject().getAsJsonObject("message");
            }

            // Check if tool_calls exists directly
            if (message.has("tool_calls")) {
                return "{\"tool_calls\":" + message.get("tool_calls").toString() + "}";
            }

            // If no tool_calls, check if content contains a JSON object
            if (message.has("content")) {
                String content = message.get("content").getAsString().trim();
                
                // Try to parse content as JSON if it looks like JSON
                if (content.startsWith("{") || content.startsWith("[")) {
                    try {
                        JsonElement contentJson = JsonParser.parseString(content);
                        
                        // Case 1: Content is a single function call
                        if (contentJson.isJsonObject()) {
                            JsonObject funcObj = contentJson.getAsJsonObject();
                            if (funcObj.has("name") && funcObj.has("arguments")) {
                                // Convert to tool_calls format
                                JsonArray toolCalls = new JsonArray();
                                JsonObject toolCall = new JsonObject();
                                JsonObject function = new JsonObject();
                                function.add("name", funcObj.get("name"));
                                function.add("arguments", funcObj.get("arguments"));
                                toolCall.add("function", function);
                                toolCalls.add(toolCall);
                                return "{\"tool_calls\":" + toolCalls.toString() + "}";
                            }
                        }
                        
                        // Case 2: Content is already a tool_calls array
                        if (contentJson.isJsonObject() && contentJson.getAsJsonObject().has("tool_calls")) {
                            return content;
                        }
                        
                        // Case 3: Content is an array of function calls
                        if (contentJson.isJsonArray()) {
                            JsonArray array = contentJson.getAsJsonArray();
                            JsonArray toolCalls = new JsonArray();
                            for (JsonElement elem : array) {
                                if (elem.isJsonObject()) {
                                    JsonObject funcObj = elem.getAsJsonObject();
                                    if (funcObj.has("name") && funcObj.has("arguments")) {
                                        JsonObject toolCall = new JsonObject();
                                        JsonObject function = new JsonObject();
                                        function.add("name", funcObj.get("name"));
                                        function.add("arguments", funcObj.get("arguments"));
                                        toolCall.add("function", function);
                                        toolCalls.add(toolCall);
                                    }
                                }
                            }
                            if (toolCalls.size() > 0) {
                                return "{\"tool_calls\":" + toolCalls.toString() + "}";
                            }
                        }
                    } catch (JsonSyntaxException e) {
                        // Content is not valid JSON, fall through to return original content
                    }
                }
                
                // If we couldn't parse as tool calls, return the original content
                return "{\"tool_calls\":[]}";
            }

            // No valid tool calls found
            return "{\"tool_calls\":[]}";
            
            } catch (JsonSyntaxException e) {
                throw new ResponseException(name, "createChatCompletionWithFunctions", 
                    ResponseException.ResponseErrorType.MALFORMED_JSON, e);
            }
        } catch (IOException e) {
            throw handleNetworkError(e, "createChatCompletionWithFunctions");
        }
    }


    @Override
    public List<String> getAvailableModels() throws APIProviderException {
        APIProviderException lastError = null;

        for (String endpoint : getModelsEndpointCandidates()) {
            Request request = new Request.Builder()
                .url(endpoint)
                .header("Accept", "application/json")
                .get()
                .build();

            try (Response response = client.newCall(request).execute()) {
                if (response.code() == 401 || response.code() == 403) {
                    throw handleHttpError(response, "getAvailableModels");
                }

                if (!response.isSuccessful()) {
                    lastError = handleHttpError(response, "getAvailableModels");
                    continue;
                }

                String responseBody = response.body() != null ? response.body().string() : "";
                List<String> modelIds = extractModelIdsFromResponse(responseBody);
                if (!modelIds.isEmpty()) {
                    return modelIds;
                }

                lastError = new APIProviderException(
                    APIProviderException.ErrorCategory.SERVICE_ERROR,
                    name,
                    "getAvailableModels",
                    "No available models were found."
                );
            } catch (IOException e) {
                lastError = handleNetworkError(e, "getAvailableModels");
            } catch (APIProviderException e) {
                lastError = e;
            }
        }

        if (lastError != null) {
            throw lastError;
        }

        throw new APIProviderException(
            APIProviderException.ErrorCategory.SERVICE_ERROR,
            name,
            "getAvailableModels",
            "No available models were found."
        );
    }

    protected List<String> getModelsEndpointCandidates() {
        List<String> candidates = new ArrayList<>();
        String baseUrl = (url != null ? url.trim() : "").replaceAll("/+$", "");

        if (baseUrl.isEmpty()) {
            candidates.add("https://api.openai.com/v1/models");
            return candidates;
        }

        if (baseUrl.endsWith("/models")) {
            candidates.add(baseUrl);
            return candidates;
        }

        candidates.add(baseUrl + "/models");
        if (!baseUrl.endsWith("/v1")) {
            candidates.add(baseUrl + "/v1/models");
        }

        return candidates;
    }

    protected List<String> extractModelIdsFromResponse(String responseBody) throws APIProviderException {
        try {
            JsonElement parsed = JsonParser.parseString(responseBody);
            if (!parsed.isJsonObject()) {
                throw new ResponseException(name, "getAvailableModels",
                    ResponseException.ResponseErrorType.MALFORMED_JSON);
            }

            JsonObject responseObj = parsed.getAsJsonObject();
            JsonArray models = responseObj.has("data") && responseObj.get("data").isJsonArray()
                ? responseObj.getAsJsonArray("data")
                : new JsonArray();

            List<String> modelIds = new ArrayList<>();
            for (JsonElement model : models) {
                if (model.isJsonObject() && model.getAsJsonObject().has("id")) {
                    modelIds.add(model.getAsJsonObject().get("id").getAsString());
                }
            }
            return modelIds;
        } catch (JsonSyntaxException e) {
            throw new ResponseException(name, "getAvailableModels",
                ResponseException.ResponseErrorType.MALFORMED_JSON, e);
        }
    }

    @Override
    public void getEmbeddingsAsync(String text, EmbeddingCallback callback) {
        JsonObject payload = new JsonObject();
        payload.addProperty("model", OPENAI_EMBEDDING_MODEL);
        payload.addProperty("input", text);
        executeEmbeddingsWithRetry(payload, callback, "get_embeddings", 0);
    }

    /**
     * Execute embeddings request with retry logic for rate limits and transient errors.
     */
    private void executeEmbeddingsWithRetry(JsonObject payload, EmbeddingCallback callback,
                                            String operation, int attemptNumber) {
        if (isCancelled) {
            callback.onError(new StreamCancelledException(name, operation,
                StreamCancelledException.CancellationReason.USER_REQUESTED));
            return;
        }

        Request request = new Request.Builder()
            .url(super.getUrl() + OPENAI_EMBEDDINGS_ENDPOINT)
            .post(RequestBody.create(gson.toJson(payload), JSON))
            .build();

        client.newCall(request).enqueue(new Callback() {
            @Override
            public void onFailure(Call call, IOException e) {
                if (call.isCanceled()) {
                    callback.onError(new StreamCancelledException(name, operation,
                        StreamCancelledException.CancellationReason.USER_REQUESTED, e));
                    return;
                }

                APIProviderException error = handleNetworkError(e, operation);
                if (shouldRetryStreaming(error, attemptNumber)) {
                    retryEmbeddingsAfterDelay(payload, callback, operation, attemptNumber, error);
                } else {
                    callback.onError(error);
                }
            }

            @Override
            public void onResponse(Call call, Response response) throws IOException {
                try (ResponseBody responseBody = response.body()) {
                    if (!response.isSuccessful()) {
                        APIProviderException error = handleHttpError(response, operation);
                        if (shouldRetryStreaming(error, attemptNumber)) {
                            retryEmbeddingsAfterDelay(payload, callback, operation, attemptNumber, error);
                        } else {
                            callback.onError(error);
                        }
                        return;
                    }

                    if (responseBody == null) {
                        callback.onError(new ResponseException(name, operation,
                            ResponseException.ResponseErrorType.EMPTY_RESPONSE));
                        return;
                    }

                    try {
                        String responseBodyStr = responseBody.string();
                        JsonObject responseObj = gson.fromJson(responseBodyStr, JsonObject.class);

                        if (!responseObj.has("data")) {
                            callback.onError(new ResponseException(name, operation,
                                ResponseException.ResponseErrorType.MISSING_REQUIRED_FIELD));
                            return;
                        }

                        JsonArray dataArray = responseObj.getAsJsonArray("data");
                        if (dataArray.size() == 0) {
                            callback.onError(new ResponseException(name, operation,
                                "No embedding data in response"));
                            return;
                        }

                        JsonObject firstElement = dataArray.get(0).getAsJsonObject();
                        if (!firstElement.has("embedding")) {
                            callback.onError(new ResponseException(name, operation,
                                ResponseException.ResponseErrorType.MISSING_REQUIRED_FIELD));
                            return;
                        }

                        JsonArray embedding = firstElement.getAsJsonArray("embedding");

                        double[] embeddingArray = new double[embedding.size()];
                        for (int i = 0; i < embedding.size(); i++) {
                            embeddingArray[i] = embedding.get(i).getAsDouble();
                        }

                        callback.onSuccess(embeddingArray);
                    } catch (JsonSyntaxException e) {
                        callback.onError(new ResponseException(name, operation,
                            ResponseException.ResponseErrorType.MALFORMED_JSON, e));
                    } catch (NumberFormatException e) {
                        callback.onError(new ResponseException(name, operation,
                            "Invalid embedding format: " + e.getMessage()));
                    }
                } catch (IOException e) {
                    callback.onError(new ResponseException(name, operation,
                        ResponseException.ResponseErrorType.STREAM_INTERRUPTED, e));
                }
            }
        });
    }

    /**
     * Retry embeddings request after appropriate delay.
     */
    private void retryEmbeddingsAfterDelay(JsonObject payload, EmbeddingCallback callback,
                                           String operation, int attemptNumber, APIProviderException error) {
        int nextAttempt = attemptNumber + 1;
        int waitTimeMs = calculateStreamingRetryWait(error);

        ghidra.util.Msg.warn(this, String.format("Embeddings retry %d/%d for %s: %s. Waiting %d seconds...",
            nextAttempt, MAX_STREAMING_RETRIES, operation,
            error.getCategory().getDisplayName(), waitTimeMs / 1000));

        new Thread(() -> {
            try {
                Thread.sleep(waitTimeMs);
                if (!isCancelled) {
                    executeEmbeddingsWithRetry(payload, callback, operation, nextAttempt);
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                callback.onError(new StreamCancelledException(name, operation,
                    StreamCancelledException.CancellationReason.USER_REQUESTED));
            }
        }, "OpenAIPlatformApiProvider-EmbeddingsRetry").start();
    }

    private JsonObject buildChatCompletionPayload(List<ChatMessage> messages, boolean stream) {
        JsonObject payload = new JsonObject();
        payload.addProperty("model", super.getModel());

        // Handle different token field names based on model
        String modelName = super.getModel();
        if (modelName != null && (modelName.startsWith("o1-") || modelName.startsWith("o3-") || modelName.startsWith("o4-") || modelName.startsWith("gpt-5"))) {
            payload.addProperty("max_completion_tokens", super.getMaxTokens());
        } else {
            payload.addProperty("max_tokens", super.getMaxTokens());
        }
        
        payload.addProperty("stream", stream);

        // Add reasoning_effort if configured
        ReasoningConfig reasoning = getReasoningConfig();
        if (reasoning != null && reasoning.isEnabled()) {
            payload.addProperty("reasoning_effort", reasoning.getEffortString());
        }

        JsonArray messagesArray = new JsonArray();
        for (ChatMessage message : messages) {
            JsonObject messageObj = new JsonObject();
            messageObj.addProperty("role", message.getRole());
            
            // Handle content - tool messages MUST always have content (even empty string)
            if (message.getContent() != null) {
                messageObj.addProperty("content", message.getContent());
            } else if ("tool".equals(message.getRole())) {
                // OpenAI requires content field for tool messages, even if empty
                messageObj.addProperty("content", "");
            }

            // Include reasoning_content for assistant messages (required by DeepSeek thinking mode)
            if (ChatMessage.ChatMessageRole.ASSISTANT.equals(message.getRole()) &&
                    message.getThinkingContent() != null && !message.getThinkingContent().isEmpty()) {
                messageObj.addProperty("reasoning_content", message.getThinkingContent());
            }

            // Handle tool calls for assistant messages
            if (message.getToolCalls() != null) {
                messageObj.add("tool_calls", message.getToolCalls());
            }

            // Handle tool call ID for tool response messages
            if (message.getToolCallId() != null) {
                messageObj.addProperty("tool_call_id", message.getToolCallId());
            }
            
            messagesArray.add(messageObj);
        }
        // Last-line-of-defense: validate tool_call/result pairing in the payload
        sanitizeToolCallsInPayload(messagesArray);

        payload.add("messages", messagesArray);

        return payload;
    }

    /**
     * Sanitize the messages array to prevent orphaned tool_calls from reaching the API.
     * For each assistant message with tool_calls, verifies matching tool result messages exist.
     * If not, removes the tool_calls or inserts placeholder tool results.
     */
    private void sanitizeToolCallsInPayload(JsonArray messagesArray) {
        for (int i = 0; i < messagesArray.size(); i++) {
            JsonObject msg = messagesArray.get(i).getAsJsonObject();
            if (!"assistant".equals(getStringField(msg, "role"))) continue;
            if (!msg.has("tool_calls") || msg.get("tool_calls").isJsonNull()) continue;

            JsonArray toolCalls = msg.getAsJsonArray("tool_calls");
            if (toolCalls.size() == 0) continue;

            // Collect expected tool_call IDs
            java.util.List<String> expectedIds = new java.util.ArrayList<>();
            for (int tc = 0; tc < toolCalls.size(); tc++) {
                JsonObject tcObj = toolCalls.get(tc).getAsJsonObject();
                String id = getStringField(tcObj, "id");
                if (id != null && !id.isEmpty()) {
                    expectedIds.add(id);
                }
            }

            if (expectedIds.isEmpty()) {
                // All IDs are null/empty - remove tool_calls
                msg.remove("tool_calls");
                ghidra.util.Msg.warn(this, "Payload sanitization: removed tool_calls with null/empty IDs at message " + i);
                continue;
            }

            // Check for matching tool result messages after this assistant message
            java.util.Set<String> foundIds = new java.util.HashSet<>();
            for (int j = i + 1; j < messagesArray.size(); j++) {
                JsonObject resultMsg = messagesArray.get(j).getAsJsonObject();
                String role = getStringField(resultMsg, "role");
                if ("tool".equals(role)) {
                    String tcId = getStringField(resultMsg, "tool_call_id");
                    if (tcId != null) foundIds.add(tcId);
                } else if ("assistant".equals(role) || "user".equals(role)) {
                    break;
                }
            }

            java.util.List<String> missingIds = new java.util.ArrayList<>();
            for (String id : expectedIds) {
                if (!foundIds.contains(id)) {
                    missingIds.add(id);
                }
            }

            if (missingIds.isEmpty()) continue;

            if (missingIds.size() == expectedIds.size()) {
                // No results at all - remove tool_calls from assistant message
                msg.remove("tool_calls");
                ghidra.util.Msg.warn(this, "Payload sanitization: removed orphaned tool_calls at message " + i +
                    " (no matching results for " + expectedIds.size() + " tool calls)");
            } else {
                // Insert placeholder results for missing IDs
                int insertAt = i + 1;
                for (int j = i + 1; j < messagesArray.size(); j++) {
                    if ("tool".equals(getStringField(messagesArray.get(j).getAsJsonObject(), "role"))) {
                        insertAt = j + 1;
                    } else {
                        break;
                    }
                }
                for (String missingId : missingIds) {
                    JsonObject placeholder = new JsonObject();
                    placeholder.addProperty("role", "tool");
                    placeholder.addProperty("tool_call_id", missingId);
                    placeholder.addProperty("content", "Error: Tool execution result was lost.");
                    // JsonArray doesn't have an insert method, so rebuild
                    // We'll add at the end and it will be in the right group
                    messagesArray.add(placeholder);
                    ghidra.util.Msg.warn(this, "Payload sanitization: inserted placeholder for tool_call_id=" + missingId);
                }
                // Re-order: move placeholders to the correct position
                reorderToolResults(messagesArray);
            }
        }
    }

    /**
     * Reorder messages so tool results immediately follow their assistant message.
     */
    private void reorderToolResults(JsonArray messagesArray) {
        // Build a corrected list
        java.util.List<JsonObject> ordered = new java.util.ArrayList<>();
        for (int i = 0; i < messagesArray.size(); i++) {
            ordered.add(messagesArray.get(i).getAsJsonObject());
        }

        java.util.List<JsonObject> result = new java.util.ArrayList<>();
        java.util.Set<Integer> processed = new java.util.HashSet<>();

        for (int i = 0; i < ordered.size(); i++) {
            if (processed.contains(i)) continue;
            JsonObject msg = ordered.get(i);
            result.add(msg);
            processed.add(i);

            // If this is an assistant with tool_calls, collect all tool results for it
            if ("assistant".equals(getStringField(msg, "role")) &&
                msg.has("tool_calls") && !msg.get("tool_calls").isJsonNull()) {

                JsonArray toolCalls = msg.getAsJsonArray("tool_calls");
                java.util.Set<String> tcIds = new java.util.HashSet<>();
                for (int tc = 0; tc < toolCalls.size(); tc++) {
                    String id = getStringField(toolCalls.get(tc).getAsJsonObject(), "id");
                    if (id != null) tcIds.add(id);
                }

                // Find all matching tool results anywhere in the array
                for (int j = 0; j < ordered.size(); j++) {
                    if (processed.contains(j)) continue;
                    JsonObject candidate = ordered.get(j);
                    if ("tool".equals(getStringField(candidate, "role"))) {
                        String candidateId = getStringField(candidate, "tool_call_id");
                        if (candidateId != null && tcIds.contains(candidateId)) {
                            result.add(candidate);
                            processed.add(j);
                        }
                    }
                }
            }
        }

        // Replace contents of messagesArray
        while (messagesArray.size() > 0) {
            messagesArray.remove(0);
        }
        for (JsonObject msg : result) {
            messagesArray.add(msg);
        }
    }

    /**
     * Safely extract a string field from a JsonObject.
     */
    private String getStringField(JsonObject obj, String field) {
        if (obj.has(field)) {
            JsonElement el = obj.get(field);
            if (el != null && !el.isJsonNull() && el.isJsonPrimitive()) {
                return el.getAsString();
            }
        }
        return null;
    }

    private String extractContentFromResponse(JsonObject responseObj) {
        return responseObj.getAsJsonArray("choices")
            .get(0).getAsJsonObject()
            .getAsJsonObject("message")
            .get("content").getAsString();
    }

    private String extractDeltaContent(JsonObject chunk) {
        try {
            JsonObject delta = chunk.getAsJsonArray("choices")
                .get(0).getAsJsonObject()
                .getAsJsonObject("delta");
            
            if (delta.has("content")) {
                return delta.get("content").getAsString();
            }
        } catch (Exception e) {
            // Handle any JSON parsing errors silently and return null
        }
        return null;
    }

    /**
     * Interface for handling streaming responses with function calling support.
     */
    public interface StreamingFunctionHandler {
        /**
         * Called when a text delta is received.
         * @param textDelta The incremental text content
         */
        void onTextUpdate(String textDelta);

        /**
         * Called when streaming is complete and all data is available.
         * @param stopReason The reason streaming stopped (e.g., "stop", "tool_calls")
         * @param fullText The complete text content
         * @param toolCalls List of tool calls (empty if none)
         */
        void onStreamComplete(String stopReason, String fullText, String reasoningContent, List<ToolCall> toolCalls);

        /**
         * Called when an error occurs during streaming.
         * @param error The error that occurred
         */
        void onError(Throwable error);

        /**
         * Called to check if streaming should continue.
         * @return true if streaming should continue, false to cancel
         */
        boolean shouldContinue();
    }

    /**
     * Represents a tool call from the LLM.
     */
    public static class ToolCall {
        public final String id;
        public final String name;
        public final String arguments;

        public ToolCall(String id, String name, String arguments) {
            this.id = id;
            this.name = name;
            this.arguments = arguments;
        }
    }

    /**
     * Stream chat completion with function calling support.
     * This method streams text content in real-time while buffering tool calls.
     */
    public void streamChatCompletionWithFunctions(
        List<ChatMessage> messages,
        List<Map<String, Object>> functions,
        StreamingFunctionHandler handler
    ) throws APIProviderException {
        streamChatCompletionWithFunctions(messages, functions, ToolChoiceMode.AUTO, handler);
    }

    public void streamChatCompletionWithFunctions(
        List<ChatMessage> messages,
        List<Map<String, Object>> functions,
        ToolChoiceMode toolChoiceMode,
        StreamingFunctionHandler handler
    ) throws APIProviderException {
        JsonObject payload = buildChatCompletionPayload(messages, true);
        payload.add("tools", gson.toJsonTree(functions));
        payload.addProperty("tool_choice",
            (toolChoiceMode != null ? toolChoiceMode : ToolChoiceMode.AUTO).toOpenAIToolChoice(messages));
        executeStreamingFunctionsWithRetry(payload, handler, "stream_chat_completion_with_functions", 0);
    }

    /**
     * Execute streaming with functions request with retry logic for rate limits and transient errors.
     */
    private void executeStreamingFunctionsWithRetry(JsonObject payload, StreamingFunctionHandler handler,
                                                    String operation, int attemptNumber) {
        if (isCancelled) {
            handler.onError(new StreamCancelledException(name, operation,
                StreamCancelledException.CancellationReason.USER_REQUESTED));
            return;
        }

        Request request = new Request.Builder()
            .url(url + OPENAI_CHAT_ENDPOINT)
            .post(RequestBody.create(gson.toJson(payload), JSON))
            .build();

        client.newCall(request).enqueue(new Callback() {
            @Override
            public void onFailure(Call call, IOException e) {
                if (call.isCanceled()) {
                    handler.onError(new StreamCancelledException(name, operation,
                        StreamCancelledException.CancellationReason.USER_REQUESTED, e));
                    return;
                }

                APIProviderException error = handleNetworkError(e, operation);
                if (shouldRetryStreaming(error, attemptNumber)) {
                    retryStreamingFunctionsAfterDelay(payload, handler, operation, attemptNumber, error);
                } else {
                    handler.onError(error);
                }
            }

            @Override
            public void onResponse(Call call, Response response) throws IOException {
                try (ResponseBody responseBody = response.body()) {
                    if (!response.isSuccessful()) {
                        APIProviderException error = handleHttpError(response, operation);
                        if (shouldRetryStreaming(error, attemptNumber)) {
                            retryStreamingFunctionsAfterDelay(payload, handler, operation, attemptNumber, error);
                        } else {
                            handler.onError(error);
                        }
                        return;
                    }

                    if (responseBody == null) {
                        handler.onError(new ResponseException(name, operation,
                            ResponseException.ResponseErrorType.EMPTY_RESPONSE));
                        return;
                    }

                    BufferedSource source = responseBody.source();
                    StringBuilder textBuilder = new StringBuilder();
                    StringBuilder reasoningBuilder = new StringBuilder();
                    java.util.Map<Integer, ToolCallAccumulator> toolCallsMap = new java.util.HashMap<>();
                    String finishReason = "stop";

                    try {
                        while (!source.exhausted() && !isCancelled && handler.shouldContinue()) {
                            String line = source.readUtf8Line();
                            if (line == null || line.isEmpty()) continue;

                            if (line.startsWith("data: ")) {
                                String data = line.substring(6).trim();
                                if (data.equals("[DONE]")) {
                                    // Process complete - convert accumulated tool calls
                                    List<ToolCall> toolCalls = new java.util.ArrayList<>();
                                    toolCallsMap.entrySet().stream()
                                        .sorted(java.util.Map.Entry.comparingByKey())
                                        .forEach(entry -> {
                                            ToolCallAccumulator acc = entry.getValue();
                                            // Validate arguments - default to {} if empty
                                            String args = acc.argumentsBuffer.toString().trim();
                                            if (args.isEmpty()) {
                                                args = "{}";
                                            }
                                            // Generate fallback ID if streaming didn't capture one
                                            String tcId = acc.id;
                                            if (tcId == null || tcId.isEmpty()) {
                                                tcId = "call_stream_" + entry.getKey() + "_" + System.currentTimeMillis();
                                                ghidra.util.Msg.warn(OpenAIPlatformApiProvider.this,
                                                    "Streaming tool call at index " + entry.getKey() +
                                                    " had no ID, generated fallback: " + tcId);
                                            }
                                            toolCalls.add(new ToolCall(tcId, acc.name, args));
                                        });

                                    handler.onStreamComplete(finishReason, textBuilder.toString(),
                                        reasoningBuilder.toString(), toolCalls);
                                    return;
                                }

                                try {
                                    JsonObject chunk = gson.fromJson(data, JsonObject.class);

                                    if (chunk.has("choices")) {
                                        JsonArray choices = chunk.getAsJsonArray("choices");
                                        if (choices.size() > 0) {
                                            JsonObject choice = choices.get(0).getAsJsonObject();

                                            // Handle delta
                                            if (choice.has("delta")) {
                                                JsonObject delta = choice.getAsJsonObject("delta");

                                                // Stream text content immediately
                                                if (delta.has("content") && !delta.get("content").isJsonNull()) {
                                                    String content = delta.get("content").getAsString();
                                                    textBuilder.append(content);
                                                    handler.onTextUpdate(content);
                                                }

                                                // Capture reasoning_content (DeepSeek thinking mode)
                                                if (delta.has("reasoning_content") && !delta.get("reasoning_content").isJsonNull()) {
                                                    reasoningBuilder.append(delta.get("reasoning_content").getAsString());
                                                }

                                                // Buffer tool calls
                                                if (delta.has("tool_calls")) {
                                                    JsonArray toolCallDeltas = delta.getAsJsonArray("tool_calls");
                                                    for (JsonElement tcElement : toolCallDeltas) {
                                                        JsonObject toolCallDelta = tcElement.getAsJsonObject();
                                                        int index = toolCallDelta.has("index") ? toolCallDelta.get("index").getAsInt() : 0;

                                                        ToolCallAccumulator acc = toolCallsMap.computeIfAbsent(index, k -> new ToolCallAccumulator());

                                                        if (toolCallDelta.has("id") && !toolCallDelta.get("id").isJsonNull()) {
                                                            acc.id = toolCallDelta.get("id").getAsString();
                                                        }

                                                        if (toolCallDelta.has("function")) {
                                                            JsonObject functionDelta = toolCallDelta.getAsJsonObject("function");
                                                            if (functionDelta.has("name") && !functionDelta.get("name").isJsonNull()) {
                                                                acc.name = functionDelta.get("name").getAsString();
                                                            }
                                                            if (functionDelta.has("arguments") && !functionDelta.get("arguments").isJsonNull()) {
                                                                acc.argumentsBuffer.append(functionDelta.get("arguments").getAsString());
                                                            }
                                                        }
                                                    }
                                                }
                                            }

                                            // Capture finish_reason
                                            if (choice.has("finish_reason") && !choice.get("finish_reason").isJsonNull()) {
                                                finishReason = choice.get("finish_reason").getAsString();
                                            }
                                        }
                                    }
                                } catch (JsonSyntaxException e) {
                                    handler.onError(new ResponseException(name, operation,
                                        ResponseException.ResponseErrorType.MALFORMED_JSON, e));
                                    return;
                                }
                            }
                        }

                        if (isCancelled) {
                            handler.onError(new StreamCancelledException(name, operation,
                                StreamCancelledException.CancellationReason.USER_REQUESTED));
                        } else if (!handler.shouldContinue()) {
                            handler.onError(new StreamCancelledException(name, operation,
                                StreamCancelledException.CancellationReason.USER_REQUESTED));
                        }
                    } catch (IOException e) {
                        handler.onError(new ResponseException(name, operation,
                            ResponseException.ResponseErrorType.STREAM_INTERRUPTED, e));
                    }
                }
            }
        });
    }

    /**
     * Retry streaming with functions request after appropriate delay.
     */
    private void retryStreamingFunctionsAfterDelay(JsonObject payload, StreamingFunctionHandler handler,
                                                   String operation, int attemptNumber, APIProviderException error) {
        int nextAttempt = attemptNumber + 1;
        int waitTimeMs = calculateStreamingRetryWait(error);

        ghidra.util.Msg.warn(this, String.format("Streaming functions retry %d/%d for %s: %s. Waiting %d seconds...",
            nextAttempt, MAX_STREAMING_RETRIES, operation,
            error.getCategory().getDisplayName(), waitTimeMs / 1000));

        new Thread(() -> {
            try {
                Thread.sleep(waitTimeMs);
                if (!isCancelled) {
                    executeStreamingFunctionsWithRetry(payload, handler, operation, nextAttempt);
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                handler.onError(new StreamCancelledException(name, operation,
                    StreamCancelledException.CancellationReason.USER_REQUESTED));
            }
        }, "OpenAIPlatformApiProvider-StreamFunctionsRetry").start();
    }

    /**
     * Helper class to accumulate tool call deltas during streaming.
     */
    private static class ToolCallAccumulator {
        String id;
        String name;
        final StringBuilder argumentsBuffer = new StringBuilder();
    }

    public void cancelRequest() {
        isCancelled = true;
    }

    @Override
    protected String extractApiErrorCode(String responseBody) {
        if (responseBody == null || responseBody.isEmpty()) {
            return null;
        }
        
        try {
            JsonObject errorObj = gson.fromJson(responseBody, JsonObject.class);
            if (errorObj.has("error")) {
                JsonElement errorElement = errorObj.get("error");
                if (errorElement.isJsonObject()) {
                    JsonObject error = errorElement.getAsJsonObject();
                    if (error.has("type")) {
                        JsonElement typeElement = error.get("type");
                        if (typeElement != null && !typeElement.isJsonNull()) {
                            return typeElement.getAsString();
                        }
                    } else if (error.has("code")) {
                        JsonElement codeElement = error.get("code");
                        if (codeElement != null && !codeElement.isJsonNull()) {
                            return codeElement.getAsString();
                        }
                    }
                }
            }
        } catch (JsonSyntaxException e) {
            // Ignore parsing errors
        }

        return null;
    }

    @Override
    protected String extractErrorMessage(String responseBody, int statusCode) {
        if (responseBody == null || responseBody.isEmpty()) {
            return null;
        }

        try {
            JsonObject errorObj = gson.fromJson(responseBody, JsonObject.class);
            if (errorObj.has("error")) {
                JsonElement errorElement = errorObj.get("error");
                if (errorElement.isJsonPrimitive()) {
                    return errorElement.getAsString();
                }
                if (errorElement.isJsonObject()) {
                    JsonObject error = errorElement.getAsJsonObject();
                    if (error.has("message")) {
                        JsonElement messageElement = error.get("message");
                        if (messageElement != null && !messageElement.isJsonNull()) {
                            return messageElement.getAsString();
                        }
                    }
                }
            }
        } catch (JsonSyntaxException e) {
            // Ignore parsing errors and fall back to parent implementation
        }
        
        // Fallback to parent implementation
        return super.extractErrorMessage(responseBody, statusCode);
    }
    
    @Override
    protected Integer extractRetryAfter(Response response, String responseBody) {
        // First check the parent implementation for standard headers
        Integer retryAfter = super.extractRetryAfter(response, responseBody);
        if (retryAfter != null) {
            return retryAfter;
        }
        
        // Check OpenAI-specific retry information in response body
        if (responseBody != null) {
            try {
                JsonObject errorObj = gson.fromJson(responseBody, JsonObject.class);
                if (errorObj.has("error")) {
                    JsonObject error = errorObj.getAsJsonObject("error");
                    if (error.has("retry_after")) {
                        return error.get("retry_after").getAsInt();
                    }
                }
            } catch (Exception e) {
                // Ignore parsing errors
            }
        }
        
        return null;
    }
}
