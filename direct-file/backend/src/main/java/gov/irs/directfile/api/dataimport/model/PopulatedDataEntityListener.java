package gov.irs.directfile.api.dataimport.model;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.persistence.PostLoad;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import gov.irs.directfile.models.encryption.DataEncryptDecrypt;
import gov.irs.directfile.models.encryption.EncryptionContextMismatchException;
import gov.irs.directfile.models.encryption.EncryptionPurpose;
import gov.irs.directfile.models.encryption.GenericStringEncryptor;

@Component
@Slf4j
public class PopulatedDataEntityListener {
    private GenericStringEncryptor genericStringEncryptor;
    private ObjectMapper objectMapper;

    @Autowired
    public void configure(DataEncryptDecrypt dataEncryptDecrypt, ObjectMapper objectMapper) {
        genericStringEncryptor = new GenericStringEncryptor(dataEncryptDecrypt);
        this.objectMapper = objectMapper;
    }

    @PostLoad
    public <T extends PopulatedData> void decryptColumn(T populatedData) {
        try {
            // Legacy-tolerant by design: this column's writer lives outside this repository, so
            // this codebase cannot migrate it to carry a purpose. See spec section 2.3. Lift this
            // when that writer adopts the schema.
            String decrypted = genericStringEncryptor.convertToEntityAttributeLegacyTolerant(
                    populatedData.getDataCipherText(), EncryptionPurpose.DATA_IMPORT_POPULATED_DATA);

            JsonNode jsonNode;
            jsonNode = objectMapper.readTree(decrypted);
            populatedData.setData(jsonNode);
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
    }
}
