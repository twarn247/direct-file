package gov.irs.directfile.api.dataimport.model;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import gov.irs.directfile.models.encryption.DataEncryptDecrypt;
import gov.irs.directfile.models.encryption.EncryptionContextMismatchException;
import gov.irs.directfile.models.encryption.EncryptionPurpose;
import gov.irs.directfile.models.encryption.GenericStringEncryptor;

@Component
@Slf4j
public class RawResponseDecryptor {
    private final GenericStringEncryptor genericStringEncryptor;
    private final ObjectMapper objectMapper;

    public RawResponseDecryptor(DataEncryptDecrypt dataEncryptDecrypt, ObjectMapper objectMapper) {
        this.genericStringEncryptor = new GenericStringEncryptor(dataEncryptDecrypt);
        this.objectMapper = objectMapper;
    }

    public JsonNode decryptRawResponse(PopulatedData populatedData) {
        try {
            // Legacy-tolerant by design: this column's writer lives outside this repository, so
            // this codebase cannot migrate it to carry a purpose. See spec section 2.3. Lift this
            // when that writer adopts the schema.
            String decrypted = genericStringEncryptor.convertToEntityAttributeLegacyTolerant(
                    populatedData.getRawDataCipherText(), EncryptionPurpose.DATA_IMPORT_RAW_RESPONSE);

            return objectMapper.readTree(decrypted);
        } catch (EncryptionContextMismatchException e) {
            // A blob in this column is tagged with some other purpose. Decryption was refused and
            // the plaintext discarded; surfaced under its own marker so it is not lost among parse
            // failures. Behavior is otherwise unchanged: the field stays unset.
            log.error(
                    "{}: refused to decrypt data column in populated_data. Error: {}",
                    EncryptionContextMismatchException.MARKER,
                    e.getMessage());
        } catch (Exception e) {
            log.error(
                    "Failed to decrypt / parse data column in populated_data. Exception: {}. Error: {}",
                    e.getClass().getName(),
                    e.getMessage());
        }
        return null;
    }
}
