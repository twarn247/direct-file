package gov.irs.directfile.api.taxreturn;

import jakarta.annotation.PostConstruct;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import gov.irs.directfile.api.taxreturn.models.EncryptionBackfillProgress;
import gov.irs.directfile.models.autoconfigure.EncryptionContextProperties;

/**
 * Drives the H-1 Phase B backfill on a schedule.
 *
 * <p>Off by default. One tick processes one batch and returns, so the sweep is stoppable
 * at any point — disable the flag, and it resumes from its persisted cursor when
 * re-enabled.
 */
@Component
@Slf4j
public class EncryptionBackfillWorker {

    /** Stable marker for progress lines. Operators watch this to track the sweep. */
    private static final String PROGRESS_MARKER = "ENCRYPTION_BACKFILL_PROGRESS";

    private final EncryptionBackfillService service;
    private final EncryptionContextProperties encryptionContextProperties;
    private final boolean enabled;
    private final int batchSize;

    public EncryptionBackfillWorker(
            EncryptionBackfillService service,
            EncryptionContextProperties encryptionContextProperties,
            @Value("${direct-file.encryption.backfill.enabled:false}") boolean enabled,
            @Value("${direct-file.encryption.backfill.batch-size:100}") int batchSize) {
        this.service = service;
        this.encryptionContextProperties = encryptionContextProperties;
        this.enabled = enabled;
        this.batchSize = batchSize;
    }

    /**
     * Refuses to run the backfill under enforce mode.
     *
     * <p>Under enforce, decrypt rejects untagged ciphertext — the exact population this
     * backfill exists to migrate. Every row would fail, and the cursor would advance past
     * rows that were never migrated, "completing" a sweep that did nothing.
     */
    @PostConstruct
    public void verifyRunnable() {
        if (!enabled) {
            return;
        }
        if (encryptionContextProperties.isEnforcing()) {
            throw new IllegalStateException("The encryption backfill requires "
                    + "direct-file.encryption.context-verification=warn. Under enforce, untagged "
                    + "ciphertext cannot be read, so the sweep would skip every row it exists to migrate.");
        }
        log.warn("Encryption backfill is ENABLED, batchSize={}", batchSize);
    }

    @Scheduled(fixedDelayString = "${direct-file.encryption.backfill.fixed-delay-millis:5000}", initialDelay = 30000)
    public void tick() {
        if (!enabled) {
            return;
        }

        // Tax returns first, then submissions. One table at a time keeps the load
        // predictable and makes the progress log unambiguous.
        EncryptionBackfillService.BatchResult returns =
                service.processNextBatch(EncryptionBackfillProgress.TAX_RETURNS, batchSize);
        if (!returns.complete()) {
            logProgress(EncryptionBackfillProgress.TAX_RETURNS, returns);
            return;
        }

        EncryptionBackfillService.BatchResult submissions =
                service.processNextBatch(EncryptionBackfillProgress.TAX_RETURN_SUBMISSIONS, batchSize);
        if (!submissions.complete()) {
            logProgress(EncryptionBackfillProgress.TAX_RETURN_SUBMISSIONS, submissions);
        }
    }

    private void logProgress(String table, EncryptionBackfillService.BatchResult result) {
        log.info(
                "{}: table={}, attempted={}, succeeded={}",
                PROGRESS_MARKER,
                table,
                result.attempted(),
                result.succeeded());
    }
}
