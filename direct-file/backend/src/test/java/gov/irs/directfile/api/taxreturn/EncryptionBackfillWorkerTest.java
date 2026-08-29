package gov.irs.directfile.api.taxreturn;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import gov.irs.directfile.api.taxreturn.models.EncryptionBackfillProgress;
import gov.irs.directfile.api.taxreturn.submissions.lock.AdvisoryLockRepository;
import gov.irs.directfile.models.autoconfigure.EncryptionContextProperties;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class EncryptionBackfillWorkerTest {

    @Mock
    private EncryptionBackfillService service;

    @Mock
    private AdvisoryLockRepository advisoryLockRepository;

    private EncryptionContextProperties warnMode() {
        EncryptionContextProperties properties = new EncryptionContextProperties();
        properties.setContextVerification(EncryptionContextProperties.WARN);
        return properties;
    }

    private EncryptionContextProperties enforceMode() {
        EncryptionContextProperties properties = new EncryptionContextProperties();
        properties.setContextVerification(EncryptionContextProperties.ENFORCE);
        return properties;
    }

    @Test
    void refusesToStartUnderEnforceMode() {
        EncryptionBackfillWorker worker =
                new EncryptionBackfillWorker(service, enforceMode(), advisoryLockRepository, true, 100);

        assertThatThrownBy(worker::verifyRunnable)
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("warn");
    }

    @Test
    void startsUnderWarnMode() {
        EncryptionBackfillWorker worker =
                new EncryptionBackfillWorker(service, warnMode(), advisoryLockRepository, true, 100);

        worker.verifyRunnable();
    }

    @Test
    void doesNothingWhenDisabled() {
        EncryptionBackfillWorker worker =
                new EncryptionBackfillWorker(service, warnMode(), advisoryLockRepository, false, 100);

        worker.tick();

        verify(service, never()).processNextBatch(any(), anyInt());
        // Disabled short-circuits before ever touching the lock, so an idle replica with
        // the flag off never contends for it.
        verify(advisoryLockRepository, never()).acquireLock(anyInt());
    }

    @Test
    void doesNothingWhenAnotherInstanceHoldsTheLock() {
        when(advisoryLockRepository.acquireLock(anyInt())).thenReturn(false);
        EncryptionBackfillWorker worker =
                new EncryptionBackfillWorker(service, warnMode(), advisoryLockRepository, true, 100);

        worker.tick();

        verify(service, never()).processNextBatch(any(), anyInt());
        verify(advisoryLockRepository, never()).releaseLock(anyInt());
    }

    @Test
    void releasesTheLockAfterATick() {
        when(advisoryLockRepository.acquireLock(anyInt())).thenReturn(true);
        when(advisoryLockRepository.releaseLock(anyInt())).thenReturn(true);
        when(service.processNextBatch(eq(EncryptionBackfillProgress.TAX_RETURNS), anyInt()))
                .thenReturn(new EncryptionBackfillService.BatchResult(0, 0, true));
        when(service.processNextBatch(eq(EncryptionBackfillProgress.TAX_RETURN_SUBMISSIONS), anyInt()))
                .thenReturn(new EncryptionBackfillService.BatchResult(0, 0, true));
        EncryptionBackfillWorker worker =
                new EncryptionBackfillWorker(service, warnMode(), advisoryLockRepository, true, 100);

        worker.tick();

        verify(advisoryLockRepository).releaseLock(anyInt());
    }

    @Test
    void releasesTheLockEvenWhenABatchThrows() {
        when(advisoryLockRepository.acquireLock(anyInt())).thenReturn(true);
        when(advisoryLockRepository.releaseLock(anyInt())).thenReturn(true);
        when(service.processNextBatch(eq(EncryptionBackfillProgress.TAX_RETURNS), anyInt()))
                .thenThrow(new RuntimeException("boom"));
        EncryptionBackfillWorker worker =
                new EncryptionBackfillWorker(service, warnMode(), advisoryLockRepository, true, 100);

        assertThatThrownBy(worker::tick).isInstanceOf(RuntimeException.class);

        verify(advisoryLockRepository).releaseLock(anyInt());
    }

    @Test
    void doesNotThrowWhenReleaseFailsOnADifferentConnection() {
        // Defense in depth: even if tick() ever stopped pinning one connection and unlock
        // landed on the wrong session, a failed release must not fail the tick -- it's
        // logged (ENCRYPTION_BACKFILL_ROW_FAILED-style visibility for an operator, not a
        // thrown exception) so the sweep's own work already committed is not undone by it.
        when(advisoryLockRepository.acquireLock(anyInt())).thenReturn(true);
        when(advisoryLockRepository.releaseLock(anyInt())).thenReturn(false);
        when(service.processNextBatch(eq(EncryptionBackfillProgress.TAX_RETURNS), anyInt()))
                .thenReturn(new EncryptionBackfillService.BatchResult(0, 0, true));
        when(service.processNextBatch(eq(EncryptionBackfillProgress.TAX_RETURN_SUBMISSIONS), anyInt()))
                .thenReturn(new EncryptionBackfillService.BatchResult(0, 0, true));
        EncryptionBackfillWorker worker =
                new EncryptionBackfillWorker(service, warnMode(), advisoryLockRepository, true, 100);

        worker.tick();

        verify(advisoryLockRepository).releaseLock(anyInt());
    }

    @Test
    void sweepsTaxReturnsBeforeSubmissions() {
        when(advisoryLockRepository.acquireLock(anyInt())).thenReturn(true);
        when(advisoryLockRepository.releaseLock(anyInt())).thenReturn(true);
        when(service.processNextBatch(eq(EncryptionBackfillProgress.TAX_RETURNS), anyInt()))
                .thenReturn(new EncryptionBackfillService.BatchResult(10, 10, false));
        EncryptionBackfillWorker worker =
                new EncryptionBackfillWorker(service, warnMode(), advisoryLockRepository, true, 100);

        worker.tick();

        verify(service).processNextBatch(EncryptionBackfillProgress.TAX_RETURNS, 100);
        verify(service, never()).processNextBatch(eq(EncryptionBackfillProgress.TAX_RETURN_SUBMISSIONS), anyInt());
    }

    @Test
    void movesToSubmissionsOnceTaxReturnsAreComplete() {
        when(advisoryLockRepository.acquireLock(anyInt())).thenReturn(true);
        when(advisoryLockRepository.releaseLock(anyInt())).thenReturn(true);
        when(service.processNextBatch(eq(EncryptionBackfillProgress.TAX_RETURNS), anyInt()))
                .thenReturn(new EncryptionBackfillService.BatchResult(0, 0, true));
        when(service.processNextBatch(eq(EncryptionBackfillProgress.TAX_RETURN_SUBMISSIONS), anyInt()))
                .thenReturn(new EncryptionBackfillService.BatchResult(5, 5, false));
        EncryptionBackfillWorker worker =
                new EncryptionBackfillWorker(service, warnMode(), advisoryLockRepository, true, 100);

        worker.tick();

        verify(service).processNextBatch(EncryptionBackfillProgress.TAX_RETURN_SUBMISSIONS, 100);
    }

    @Test
    void lockReleaseFailureMarkerIsStable() {
        // This constant is what the README tells operators to alert on, and it is the only
        // signal that the connection-pinning regression the README describes has occurred.
        // Changing it is a breaking change to an operational interface.
        assertThat(EncryptionBackfillWorker.LOCK_RELEASE_FAILURE_MARKER)
                .isEqualTo("ENCRYPTION_BACKFILL_LOCK_RELEASE_FAILED");
    }
}
