package gov.irs.directfile.models.encryption;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

import lombok.AllArgsConstructor;

@AllArgsConstructor
public class GenericStringEncryptor {
    private final DataEncryptDecrypt dataEncryptDecrypt;

    public String convertToDatabaseColumn(String attribute, EncryptionPurpose purpose, String actorId) {
        if (attribute == null || attribute.isEmpty()) {
            return attribute;
        }
        byte[] ciphertext = dataEncryptDecrypt.encrypt(attribute.getBytes(StandardCharsets.UTF_8), purpose, actorId);
        return Base64.getEncoder().encodeToString(ciphertext);
    }

    public String convertToEntityAttribute(String dbData, EncryptionPurpose expected) {
        if (dbData == null || dbData.isEmpty()) {
            return dbData;
        }
        byte[] ciphertext = Base64.getDecoder().decode(dbData);
        return new String(dataEncryptDecrypt.decrypt(ciphertext, expected), StandardCharsets.UTF_8);
    }

    /** See {@link DataEncryptDecrypt#decryptLegacyTolerant} — data-import populations only. */
    public String convertToEntityAttributeLegacyTolerant(String dbData, EncryptionPurpose expected) {
        if (dbData == null || dbData.isEmpty()) {
            return dbData;
        }
        byte[] ciphertext = Base64.getDecoder().decode(dbData);
        return new String(dataEncryptDecrypt.decryptLegacyTolerant(ciphertext, expected), StandardCharsets.UTF_8);
    }

    public String convertToDatabaseColumn(
            String attribute, EncryptionPurpose purpose, String actorId, String recordId) {
        if (attribute == null || attribute.isEmpty()) {
            return attribute;
        }
        byte[] ciphertext =
                dataEncryptDecrypt.encrypt(attribute.getBytes(StandardCharsets.UTF_8), purpose, actorId, recordId);
        return Base64.getEncoder().encodeToString(ciphertext);
    }

    public String convertToEntityAttribute(String dbData, EncryptionPurpose expected, String expectedRecordId) {
        if (dbData == null || dbData.isEmpty()) {
            return dbData;
        }
        byte[] ciphertext = Base64.getDecoder().decode(dbData);
        return new String(dataEncryptDecrypt.decrypt(ciphertext, expected, expectedRecordId), StandardCharsets.UTF_8);
    }
}
