package gov.irs.directfile.api.taxreturn;

import java.util.Optional;
import java.util.UUID;

import jakarta.persistence.EntityManager;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import gov.irs.directfile.api.taxreturn.models.TaxReturn;
import gov.irs.directfile.models.encryption.EncryptionContextMismatchException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class EncryptionBackfillRowServiceTest {

    @InjectMocks
    private EncryptionBackfillRowService service;

    @Mock
    private TaxReturnRepository taxReturnRepository;

    @Mock
    private TaxReturnSubmissionRepository taxReturnSubmissionRepository;

    @Mock
    private EntityManager entityManager;

    @Test
    void reencryptTaxReturn_dirtiesAndSavesTheRow() {
        UUID id = UUID.randomUUID();
        TaxReturn taxReturn = new TaxReturn();
        taxReturn.setFactsWithoutDirtyingEntity(java.util.Map.of());
        when(taxReturnRepository.findById(id)).thenReturn(Optional.of(taxReturn));

        boolean result = service.reencryptTaxReturn(id);

        assertThat(result).isTrue();
        verify(taxReturnRepository).save(taxReturn);
        verify(entityManager).flush();
    }

    @Test
    void reencryptTaxReturn_returnsFalseWhenFlushFailsAtWriteTime() {
        // @PreUpdate re-encryption only actually runs on flush, which happens after
        // save.apply() returns for an already-managed entity. A failure here (e.g. the
        // encryptor itself throwing) must be caught by the same path as a read-time failure,
        // not escape to the caller.
        UUID id = UUID.randomUUID();
        TaxReturn taxReturn = new TaxReturn();
        taxReturn.setFactsWithoutDirtyingEntity(java.util.Map.of());
        when(taxReturnRepository.findById(id)).thenReturn(Optional.of(taxReturn));
        doThrow(new EncryptionContextMismatchException("purpose mismatch"))
                .when(entityManager)
                .flush();

        boolean result = service.reencryptTaxReturn(id);

        assertThat(result).isFalse();
    }

    @Test
    void reencryptTaxReturn_returnsFalseWhenTheRowIsGone() {
        UUID id = UUID.randomUUID();
        when(taxReturnRepository.findById(id)).thenReturn(Optional.empty());

        boolean result = service.reencryptTaxReturn(id);

        assertThat(result).isFalse();
        verify(taxReturnRepository, never()).save(any());
    }

    @Test
    void reencryptTaxReturn_returnsFalseWhenTheRowCannotBeDecrypted() {
        UUID id = UUID.randomUUID();
        // @PostLoad decryption failure surfaces from findById.
        when(taxReturnRepository.findById(id)).thenThrow(new EncryptionContextMismatchException("purpose mismatch"));

        boolean result = service.reencryptTaxReturn(id);

        assertThat(result).isFalse();
        verify(taxReturnRepository, never()).save(any());
    }
}
