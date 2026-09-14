package ghidrassist.chat.transcript;

import ghidra.util.Msg;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.UUID;

/**
 * Stores oversized transcript payloads on disk and keeps lightweight DB metadata.
 */
public class TranscriptArtifactStore {
    public static final int DEFAULT_INLINE_THRESHOLD = 4000;
    public static final int DEFAULT_PREVIEW_CHARS = 1200;

    private final Path rootDirectory;
    private final int inlineThresholdChars;
    private final int previewChars;

    public TranscriptArtifactStore(Path rootDirectory) {
        this(rootDirectory, DEFAULT_INLINE_THRESHOLD, DEFAULT_PREVIEW_CHARS);
    }

    public TranscriptArtifactStore(Path rootDirectory, int inlineThresholdChars, int previewChars) {
        this.rootDirectory = rootDirectory;
        this.inlineThresholdChars = inlineThresholdChars;
        this.previewChars = previewChars;
    }

    public StoredArtifact maybeStore(int sessionId, String artifactType, String content) {
        String normalized = content != null ? content : "";
        String preview = buildPreview(normalized);
        if (normalized.length() <= inlineThresholdChars) {
            return new StoredArtifact(null, null, artifactType, preview, normalized.length(), normalized);
        }

        try {
            Path sessionDir = rootDirectory.resolve("session-" + sessionId);
            Files.createDirectories(sessionDir);

            String artifactId = UUID.randomUUID().toString();
            Path artifactPath = sessionDir.resolve(artifactId + ".txt");
            Files.writeString(artifactPath, normalized, StandardCharsets.UTF_8);

            return new StoredArtifact(
                artifactId,
                artifactPath.toAbsolutePath().toString(),
                artifactType,
                preview,
                normalized.getBytes(StandardCharsets.UTF_8).length,
                null
            );
        } catch (IOException e) {
            Msg.warn(this, "Failed to persist transcript artifact, keeping inline payload: " + e.getMessage());
            return new StoredArtifact(null, null, artifactType, preview, normalized.length(), normalized);
        }
    }

    private String buildPreview(String content) {
        if (content == null || content.isEmpty()) {
            return "";
        }
        if (content.length() <= previewChars) {
            return content;
        }
        return content.substring(0, previewChars) + "\n\n[Full output stored as artifact]";
    }

    public static class StoredArtifact {
        private final String artifactId;
        private final String storagePath;
        private final String artifactType;
        private final String previewText;
        private final int byteSize;
        private final String inlineContent;

        public StoredArtifact(String artifactId, String storagePath, String artifactType,
                              String previewText, int byteSize, String inlineContent) {
            this.artifactId = artifactId;
            this.storagePath = storagePath;
            this.artifactType = artifactType;
            this.previewText = previewText;
            this.byteSize = byteSize;
            this.inlineContent = inlineContent;
        }

        public String getArtifactId() {
            return artifactId;
        }

        public String getStoragePath() {
            return storagePath;
        }

        public String getArtifactType() {
            return artifactType;
        }

        public String getPreviewText() {
            return previewText;
        }

        public int getByteSize() {
            return byteSize;
        }

        public String getInlineContent() {
            return inlineContent;
        }
    }
}
