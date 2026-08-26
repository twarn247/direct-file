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
        } catch (EncryptionContextMismatchException e) { // NOPMD - intentionally empty, see comment below
            // A blob in this column is tagged with some other purpose. DataEncryptDecrypt.refuse
            // already logged this under its own marker before throwing, so there's nothing to add
            // here beyond leaving the field unset — this catch exists only so the mismatch doesn't
            // fall into the generic catch-all below and get logged as an ordinary parse failure.
        } catch (Exception e) {
            log.error(
                    "Failed to decrypt / parse raw_data column in populated_data. Exception: {}. Error: {}",
                    e.getClass().getName(),
                    e.getMessage());
        }
        return null;
    }
}
