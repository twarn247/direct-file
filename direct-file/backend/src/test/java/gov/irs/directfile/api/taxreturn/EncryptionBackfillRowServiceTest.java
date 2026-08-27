package gov.irs.directfile.api.taxreturn;

import java.util.Optional;
import java.util.UUID;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import gov.irs.directfile.api.taxreturn.models.TaxReturn;
import gov.irs.directfile.models.encryption.EncryptionContextMismatchException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
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

    @Test
    void reencryptTaxReturn_dirtiesAndSavesTheRow() {
        UUID id = UUID.randomUUID();
        TaxReturn taxReturn = new TaxReturn();
        taxReturn.setFactsWithoutDirtyingEntity(java.util.Map.of());
        when(taxReturnRepository.findById(id)).thenReturn(Optional.of(taxReturn));

        boolean result = service.reencryptTaxReturn(id);

        assertThat(result).isTrue();
        verify(taxReturnRepository).save(taxReturn);
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
