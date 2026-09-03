package gov.irs.directfile.api.taxreturn.models;

import com.fasterxml.jackson.databind.ObjectMapper;
import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import jakarta.persistence.PostLoad;
import jakarta.persistence.PrePersist;
import jakarta.persistence.PreUpdate;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import gov.irs.directfile.api.authentication.NullAuthenticationException;
import gov.irs.directfile.api.config.identity.IdentityAttributes;
import gov.irs.directfile.api.config.identity.IdentitySupplier;
import gov.irs.directfile.models.encryption.DataEncryptDecrypt;
import gov.irs.directfile.models.encryption.EncryptionPurpose;
import gov.irs.directfile.models.encryption.FactsEncryptor;
import gov.irs.directfile.models.encryption.GenericStringEncryptor;

@Component
@SuppressFBWarnings(value = {"ST_WRITE_TO_STATIC_FROM_INSTANCE_METHOD"})
public class TaxReturnEntityListener {
    private static IdentitySupplier identitySupplier;
    private static FactsEncryptor factsEncryptor;
    private static GenericStringEncryptor genericStringEncryptor;

    @Autowired
    public void configure(
            IdentitySupplier dfIdentitySupplier, DataEncryptDecrypt dataEncryptDecrypt, ObjectMapper objectMapper) {
        identitySupplier = dfIdentitySupplier;
        factsEncryptor = new FactsEncryptor(dataEncryptDecrypt);
        genericStringEncryptor = new GenericStringEncryptor(dataEncryptDecrypt);
    }

    @PostLoad
    public <T extends TaxReturnEntity> void decryptColumns(T taxReturn) {
        String recordId = taxReturn.getId().toString();
        taxReturn.setFactsWithoutDirtyingEntity(factsEncryptor.convertToEntityAttribute(
                taxReturn.getFactsCipherText(), EncryptionPurpose.TAX_RETURN_FACTS, recordId));
        taxReturn.setStoreWithoutDirtyingEntity(genericStringEncryptor.convertToEntityAttribute(
                taxReturn.getStoreCipherText(), EncryptionPurpose.TAX_RETURN_STORE, recordId));
    }

    @PrePersist
    @PreUpdate
    public <T extends TaxReturnEntity> void encryptColumns(T taxReturn) {
        String actorId;
        try {
            IdentityAttributes identityAttributes = identitySupplier.get();
            actorId = identityAttributes.externalId().toString();
        } catch (NullAuthenticationException e) {
            // this write was triggered by a system event (e.g. sqs message handler)
            actorId = null;
        }

        String recordId = taxReturn.getId().toString();
        taxReturn.setFactsCipherText(factsEncryptor.convertToDatabaseColumn(
                taxReturn.getFacts(), EncryptionPurpose.TAX_RETURN_FACTS, actorId, recordId));
        taxReturn.setStoreCipherText(genericStringEncryptor.convertToDatabaseColumn(
                taxReturn.getStore(), EncryptionPurpose.TAX_RETURN_STORE, actorId, recordId));
    }
}
