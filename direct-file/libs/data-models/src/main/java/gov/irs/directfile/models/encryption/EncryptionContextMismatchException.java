package gov.irs.directfile.models.encryption;

/**
 * Thrown when a ciphertext's bound encryption context does not carry the purpose the
 * caller expected. Carries no plaintext and no context values — only purpose names.
 */
public class EncryptionContextMismatchException extends RuntimeException {
    /**
     * Stable log marker, deliberately distinct from {@code ENCRYPTION_CONTEXT_LEGACY}. That one
     * counts ciphertext still waiting to be migrated and is expected during Phase A; this one
     * means a blob carried the wrong purpose and was refused, and is never expected.
     */
    public static final String MARKER = "ENCRYPTION_CONTEXT_MISMATCH";

    public EncryptionContextMismatchException(String message) {
        super(message);
    }
}
