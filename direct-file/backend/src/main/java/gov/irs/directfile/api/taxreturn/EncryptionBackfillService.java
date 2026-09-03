package gov.irs.directfile.api.taxreturn;

import java.util.List;
import java.util.UUID;

import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.Limit;
import org.springframework.stereotype.Service;

import gov.irs.directfile.api.taxreturn.models.EncryptionBackfillProgress;

/** Drives the H-1 Phase B sweep one batch at a time, tracking a resumable cursor. */
@Service
@Slf4j
public class EncryptionBackfillService {

    private final EncryptionBackfillRowService rowService;
    private final TaxReturnRepository taxReturnRepository;
    private final TaxReturnSubmissionRepository taxReturnSubmissionRepository;
    private final EncryptionBackfillProgressRepository progressRepository;

    public EncryptionBackfillService(
            EncryptionBackfillRowService rowService,
            TaxReturnRepository taxReturnRepository,
            TaxReturnSubmissionRepository taxReturnSubmissionRepository,
            EncryptionBackfillProgressRepository progressRepository) {
        this.rowService = rowService;
        this.taxReturnRepository = taxReturnRepository;
        this.taxReturnSubmissionRepository = taxReturnSubmissionRepository;
        this.progressRepository = progressRepository;
    }

    /** Outcome of one batch. {@code complete} means this table has no rows left to sweep. */
    public record BatchResult(int attempted, int succeeded, boolean complete) {
        static BatchResult finished() {
            return new BatchResult(0, 0, true);
        }
    }

    private static final UUID FIRST_CURSOR = new UUID(0L, 0L);

    /**
     * Processes one batch for {@code targetTable} and advances the persisted cursor.
     *
     * <p>Not transactional as a whole: each row commits in its own transaction
     * (REQUIRES_NEW), and the cursor advance commits separately. A crash mid-batch
     * therefore re-processes at most one batch, which is harmless — re-encrypting an
     * already-migrated row is a no-op in effect.
     */
    public BatchResult processNextBatch(String targetTable, int batchSize) {
        EncryptionBackfillProgress progress = progressRepository
                .findById(targetTable)
                .orElseGet(() -> {
                    EncryptionBackfillProgress fresh = new EncryptionBackfillProgress();
                    fresh.setTargetTable(targetTable);
                    return fresh;
                });

        if (progress.isCompleted()) {
            return BatchResult.finished();
        }

        UUID cursor = progress.getLastId() == null ? FIRST_CURSOR : progress.getLastId();
        List<UUID> ids = idsAfter(targetTable, cursor, Limit.of(batchSize));

        if (ids.isEmpty()) {
            progress.setCompleted(true);
            progressRepository.save(progress);
            log.info("Encryption backfill complete for table={}", targetTable);
            return BatchResult.finished();
        }

        int succeeded = 0;
        for (UUID id : ids) {
            // Through the injected bean, never this: REQUIRES_NEW only applies across
            // the proxy boundary.
            boolean ok = EncryptionBackfillProgress.TAX_RETURNS.equals(targetTable)
                    ? rowService.reencryptTaxReturn(id)
                    : rowService.reencryptSubmission(id);
            if (ok) {
                succeeded++;
            }
        }

        // Advance past every id in the page, including any that failed. A row that cannot
        // be migrated is reported under FAILURE_MARKER and left behind rather than retried
        // forever; leaving it would stall the sweep permanently. The counters commit in the
        // same save as the cursor, so they can never drift out of sync with it.
        progress.setLastId(ids.get(ids.size() - 1));
        progress.setAttempted(progress.getAttempted() + ids.size());
        progress.setSucceeded(progress.getSucceeded() + succeeded);
        progress.setFailed(progress.getFailed() + ids.size() - succeeded);
        progressRepository.save(progress);

        return new BatchResult(ids.size(), succeeded, false);
    }

    private List<UUID> idsAfter(String targetTable, UUID cursor, Limit limit) {
        if (EncryptionBackfillProgress.TAX_RETURNS.equals(targetTable)) {
            return taxReturnRepository.findIdsForBackfillAfter(cursor, limit);
        }
        if (EncryptionBackfillProgress.TAX_RETURN_SUBMISSIONS.equals(targetTable)) {
            return taxReturnSubmissionRepository.findIdsForBackfillAfter(cursor, limit);
        }
        throw new IllegalArgumentException("Unknown backfill target table: " + targetTable);
    }
}
