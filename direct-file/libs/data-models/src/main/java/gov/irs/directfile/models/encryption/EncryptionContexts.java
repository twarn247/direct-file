package gov.irs.directfile.models.encryption;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Builds AWS Encryption SDK encryption contexts. Every context this codebase writes
 * comes from here, so that no call site can produce an untagged one by hand.
 *
 * <p>{@code purpose} is verified on decrypt. {@code system} and {@code id} are not:
 * {@code id} records who wrote the blob, which is useful for KMS CloudTrail attribution
 * and cannot be checked at read time, because the reader is not necessarily the writer
 * and, at {@code @PostLoad}, there may be no authenticated principal at all.
 */
public final class EncryptionContexts {
    public static final String PURPOSE_KEY = "purpose";
    public static final String SYSTEM_KEY = "system";
    public static final String ID_KEY = "id";

    public static final String SYSTEM_VALUE = "DIRECT-FILE";

    private EncryptionContexts() {}

    public static Map<String, String> forPurpose(EncryptionPurpose purpose) {
        return forPurpose(purpose, null);
    }

    public static Map<String, String> forPurpose(EncryptionPurpose purpose, String actorId) {
        if (purpose == null) {
            throw new IllegalArgumentException("encryption purpose is required");
        }
        Map<String, String> context = new LinkedHashMap<>();
        context.put(PURPOSE_KEY, purpose.wireValue());
        context.put(SYSTEM_KEY, SYSTEM_VALUE);
        if (actorId != null && !actorId.isBlank()) {
            context.put(ID_KEY, actorId);
        }
        return Map.copyOf(context);
    }
}
