package gov.irs.directfile.models.encryption;

import java.util.Optional;

/**
 * What kind of plaintext a ciphertext holds. Bound into the AWS Encryption SDK
 * encryption context under the "purpose" key and verified on decrypt, so that a
 * blob of one kind cannot be substituted for a blob of another under the shared CMK.
 *
 * <p>The wire value is deliberately separate from the enum constant name. The enum
 * name can be refactored; the wire value is baked into every ciphertext ever written
 * and can never change.
 */
public enum EncryptionPurpose {
    TAX_RETURN_FACTS("tax-return-facts"),
    TAX_RETURN_STORE("tax-return-store"),
    STATE_EXPORT_TOKEN("state-export-token"),

    /**
     * Read-only in this repository: the writers of these two populations live outside it,
     * so nothing here ever encrypts under them. See the spec, §2.3.
     */
    DATA_IMPORT_POPULATED_DATA("data-import-populated-data"),
    DATA_IMPORT_RAW_RESPONSE("data-import-raw-response");

    private final String wireValue;

    EncryptionPurpose(String wireValue) {
        this.wireValue = wireValue;
    }

    public String wireValue() {
        return wireValue;
    }

    public static Optional<EncryptionPurpose> fromWireValue(String wireValue) {
        if (wireValue == null) {
            return Optional.empty();
        }
        for (EncryptionPurpose purpose : values()) {
            if (purpose.wireValue.equals(wireValue)) {
                return Optional.of(purpose);
            }
        }
        return Optional.empty();
    }
}
