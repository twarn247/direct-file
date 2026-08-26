package gov.irs.directfile.models.encryption;

import java.util.Base64;
import java.util.Map;

import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import lombok.AllArgsConstructor;

@AllArgsConstructor
@SuppressFBWarnings(value = "DM_DEFAULT_ENCODING", justification = "Initial Spotbugs Setup")
public class GenericStringEncryptor {
    private final DataEncryptDecrypt dataEncryptDecrypt;

    public String convertToDatabaseColumn(String attribute, Map<String, String> encryptionContext) {
        if (attribute == null || attribute.isEmpty()) {
            return attribute;
        }
        byte[] ciphertext = dataEncryptDecrypt.encrypt(attribute.getBytes(), encryptionContext);
        return Base64.getEncoder().encodeToString(ciphertext);
    }

    public String convertToEntityAttribute(String dbData) {
        if (dbData == null || dbData.isEmpty()) {
            return dbData;
        }
        byte[] ciphertext = Base64.getDecoder().decode(dbData);
        byte[] decrypted = dataEncryptDecrypt.decrypt(ciphertext);
        return new String(decrypted);
    }

    public String convertToDatabaseColumn(String attribute, EncryptionPurpose purpose, String actorId) {
        if (attribute == null || attribute.isEmpty()) {
            return attribute;
        }
        byte[] ciphertext = dataEncryptDecrypt.encrypt(attribute.getBytes(), purpose, actorId);
        return Base64.getEncoder().encodeToString(ciphertext);
    }

    public String convertToEntityAttribute(String dbData, EncryptionPurpose expected) {
        if (dbData == null || dbData.isEmpty()) {
            return dbData;
        }
        byte[] ciphertext = Base64.getDecoder().decode(dbData);
        return new String(dataEncryptDecrypt.decrypt(ciphertext, expected));
    }

    /** See {@link DataEncryptDecrypt#decryptLegacyTolerant} — data-import populations only. */
    public String convertToEntityAttributeLegacyTolerant(String dbData, EncryptionPurpose expected) {
        if (dbData == null || dbData.isEmpty()) {
            return dbData;
        }
        byte[] ciphertext = Base64.getDecoder().decode(dbData);
        return new String(dataEncryptDecrypt.decryptLegacyTolerant(ciphertext, expected));
    }
}
