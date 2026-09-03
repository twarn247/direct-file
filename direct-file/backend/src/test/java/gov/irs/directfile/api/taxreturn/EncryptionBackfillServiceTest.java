package gov.irs.directfile.api.taxreturn;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import gov.irs.directfile.api.taxreturn.models.EncryptionBackfillProgress;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class EncryptionBackfillServiceTest {

    @InjectMocks
    private EncryptionBackfillService service;

    @Mock
    private EncryptionBackfillRowService rowService;

    @Mock
    private TaxReturnRepository taxReturnRepository;

    @Mock
    private TaxReturnSubmissionRepository taxReturnSubmissionRepository;

    @Mock
    private EncryptionBackfillProgressRepository progressRepository;

    private static final UUID ZERO = new UUID(0L, 0L);

    @Test
    void processNextBatch_startsFromZeroWhenNoCursorExists() {
        when(progressRepository.findById(EncryptionBackfillProgress.TAX_RETURNS))
                .thenReturn(Optional.empty());
        when(taxReturnRepository.findIdsForBackfillAfter(eq(ZERO), any())).thenReturn(List.of());

        EncryptionBackfillService.BatchResult result =
                service.processNextBatch(EncryptionBackfillProgress.TAX_RETURNS, 10);

        assertThat(result.complete()).isTrue();
        assertThat(result.attempted()).isZero();
    }

    @Test
    void processNextBatch_advancesTheCursorToTheLastIdInThePage() {
        UUID a = new UUID(0L, 1L);
        UUID b = new UUID(0L, 2L);
        when(progressRepository.findById(EncryptionBackfillProgress.TAX_RETURNS))
                .thenReturn(Optional.empty());
        when(taxReturnRepository.findIdsForBackfillAfter(eq(ZERO), any())).thenReturn(List.of(a, b));
        when(rowService.reencryptTaxReturn(any())).thenReturn(true);

        EncryptionBackfillService.BatchResult result =
                service.processNextBatch(EncryptionBackfillProgress.TAX_RETURNS, 10);

        assertThat(result.attempted()).isEqualTo(2);
        assertThat(result.complete()).isFalse();

        ArgumentCaptor<EncryptionBackfillProgress> saved = ArgumentCaptor.forClass(EncryptionBackfillProgress.class);
        verify(progressRepository).save(saved.capture());
        assertThat(saved.getValue().getLastId()).isEqualTo(b);
        assertThat(saved.getValue().isCompleted()).isFalse();
    }

    @Test
    void processNextBatch_accumulatesCountersAcrossBatchesRatherThanOverwriting() {
        UUID a = new UUID(0L, 1L);
        EncryptionBackfillProgress existing = new EncryptionBackfillProgress();
        existing.setTargetTable(EncryptionBackfillProgress.TAX_RETURNS);
        existing.setLastId(new UUID(0L, 5L));
        existing.setAttempted(10);
        existing.setSucceeded(9);
        existing.setFailed(1);
        when(progressRepository.findById(EncryptionBackfillProgress.TAX_RETURNS))
                .thenReturn(Optional.of(existing));
        when(taxReturnRepository.findIdsForBackfillAfter(eq(existing.getLastId()), any()))
                .thenReturn(List.of(a));
        when(rowService.reencryptTaxReturn(a)).thenReturn(false);

        service.processNextBatch(EncryptionBackfillProgress.TAX_RETURNS, 10);

        ArgumentCaptor<EncryptionBackfillProgress> saved = ArgumentCaptor.forClass(EncryptionBackfillProgress.class);
        verify(progressRepository).save(saved.capture());
        assertThat(saved.getValue().getAttempted()).isEqualTo(11);
        assertThat(saved.getValue().getSucceeded()).isEqualTo(9);
        assertThat(saved.getValue().getFailed()).isEqualTo(2);
    }

    @Test
    void processNextBatch_advancesPastRowsThatFail() {
        UUID a = new UUID(0L, 1L);
        when(progressRepository.findById(EncryptionBackfillProgress.TAX_RETURNS))
                .thenReturn(Optional.empty());
        when(taxReturnRepository.findIdsForBackfillAfter(eq(ZERO), any())).thenReturn(List.of(a));
        when(rowService.reencryptTaxReturn(a)).thenReturn(false);

        EncryptionBackfillService.BatchResult result =
                service.processNextBatch(EncryptionBackfillProgress.TAX_RETURNS, 10);

        assertThat(result.attempted()).isEqualTo(1);
        assertThat(result.succeeded()).isZero();

        // The cursor still moved: a row that cannot be migrated must not stall the sweep.
        ArgumentCaptor<EncryptionBackfillProgress> saved = ArgumentCaptor.forClass(EncryptionBackfillProgress.class);
        verify(progressRepository).save(saved.capture());
        assertThat(saved.getValue().getLastId()).isEqualTo(a);
    }

    @Test
    void processNextBatch_marksCompleteWhenAPageComesBackEmpty() {
        EncryptionBackfillProgress existing = new EncryptionBackfillProgress();
        existing.setTargetTable(EncryptionBackfillProgress.TAX_RETURNS);
        existing.setLastId(new UUID(0L, 5L));
        when(progressRepository.findById(EncryptionBackfillProgress.TAX_RETURNS))
                .thenReturn(Optional.of(existing));
        when(taxReturnRepository.findIdsForBackfillAfter(eq(existing.getLastId()), any()))
                .thenReturn(List.of());

        EncryptionBackfillService.BatchResult result =
                service.processNextBatch(EncryptionBackfillProgress.TAX_RETURNS, 10);

        assertThat(result.complete()).isTrue();

        ArgumentCaptor<EncryptionBackfillProgress> saved = ArgumentCaptor.forClass(EncryptionBackfillProgress.class);
        verify(progressRepository).save(saved.capture());
        assertThat(saved.getValue().isCompleted()).isTrue();
    }

    @Test
    void processNextBatch_returnsCompleteWithoutWorkWhenAlreadyCompleted() {
        EncryptionBackfillProgress done = new EncryptionBackfillProgress();
        done.setTargetTable(EncryptionBackfillProgress.TAX_RETURNS);
        done.setCompleted(true);
        when(progressRepository.findById(EncryptionBackfillProgress.TAX_RETURNS))
                .thenReturn(Optional.of(done));

        EncryptionBackfillService.BatchResult result =
                service.processNextBatch(EncryptionBackfillProgress.TAX_RETURNS, 10);

        assertThat(result.complete()).isTrue();
        verify(taxReturnRepository, never()).findIdsForBackfillAfter(any(), any());
    }
}
