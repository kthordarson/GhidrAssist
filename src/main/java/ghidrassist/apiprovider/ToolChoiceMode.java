package ghidrassist.apiprovider;

import java.util.List;

/**
 * Shared tool-choice policy for provider function-calling requests.
 */
public enum ToolChoiceMode {
    AUTO {
        @Override
        public boolean usesRequiredToolPrompt() {
            return false;
        }

        @Override
        protected boolean shouldRequireToolUse(List<ChatMessage> messages) {
            return false;
        }
    },
    REQUIRED_INITIAL {
        @Override
        public boolean usesRequiredToolPrompt() {
            return true;
        }

        @Override
        protected boolean shouldRequireToolUse(List<ChatMessage> messages) {
            if (messages == null || messages.isEmpty()) {
                return true;
            }

            for (int i = messages.size() - 1; i >= 0; i--) {
                ChatMessage message = messages.get(i);
                if (message == null || message.getRole() == null) {
                    continue;
                }

                String role = message.getRole();
                if (ChatMessage.ChatMessageRole.SYSTEM.equals(role)) {
                    continue;
                }

                if (ChatMessage.ChatMessageRole.TOOL.equals(role)
                        || ChatMessage.ChatMessageRole.FUNCTION.equals(role)) {
                    return false;
                }

                return true;
            }

            return true;
        }
    };

    public abstract boolean usesRequiredToolPrompt();

    protected abstract boolean shouldRequireToolUse(List<ChatMessage> messages);

    public String toOpenAIToolChoice(List<ChatMessage> messages) {
        return shouldRequireToolUse(messages) ? "required" : "auto";
    }

    public String toAnthropicToolChoiceType(List<ChatMessage> messages) {
        return shouldRequireToolUse(messages) ? "any" : "auto";
    }

    public String toGeminiFunctionCallingMode(List<ChatMessage> messages) {
        return shouldRequireToolUse(messages) ? "ANY" : "AUTO";
    }
}
