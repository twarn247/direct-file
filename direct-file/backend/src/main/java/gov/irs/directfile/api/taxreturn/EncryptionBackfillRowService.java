package gov.irs.directfile.api.taxreturn;

import java.util.Optional;
import java.util.UUID;
import java.util.function.Function;

import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import gov.irs.directfile.api.taxreturn.models.TaxReturnEntity;

/**
 * H-1 Phase B: re-encrypts existing ciphertext so it carries a bound encryption purpose.
 *
 * <p>Contains no cryptographic code. Loading a row decrypts it via @PostLoad; dirtying it
 * and saving re-encrypts it via @PreUpdate using whatever context schema the listener
 * implements at the time. This class only drives that mechanism, one row at a time.
 *
 * <p>Deliberately a separate bean from EncryptionBackfillService: @Transactional is
 * proxy-based, so calling these methods from the batch loop on the same bean would bypass
 * REQUIRES_NEW and give every row the caller's transaction.
 */
@Service
@Slf4j
public class EncryptionBackfillRowService {

    /** Stable marker for rows the backfill could not migrate. Operators alert on this. */
    public static final String FAILURE_MARKER = "ENCRYPTION_BACKFILL_ROW_FAILED";

    private final TaxReturnRepository taxReturnRepository;
    private final TaxReturnSubmissionRepository taxReturnSubmissionRepository;

    public EncryptionBackfillRowService(
            TaxReturnRepository taxReturnRepository, TaxReturnSubmissionRepository taxReturnSubmissionRepository) {
        this.taxReturnRepository = taxReturnRepository;
        this.taxReturnSubmissionRepository = taxReturnSubmissionRepository;
    }

    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public boolean reencryptTaxReturn(UUID id) {
        return reencrypt("taxreturns", id, taxReturnRepository::findById, taxReturnRepository::save);
    }

    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public boolean reencryptSubmission(UUID id) {
        return reencrypt(
                "taxreturn_submissions",
                id,
                taxReturnSubmissionRepository::findById,
                taxReturnSubmissionRepository::save);
    }

    /**
     * Loads one row, dirties it, and saves it.
     *
     * <p>Dirtying facts alone is sufficient for both tables: encryptColumns re-encrypts
     * every ciphertext column on any @PreUpdate, not only the one that changed. That is
     * also why this works unchanged for TaxReturnSubmission, which has no store column.
     *
     * <p>Failures are swallowed and reported rather than propagated. A row that cannot be
     * decrypted must not stall the sweep — the caller advances past it, and the marker is
     * what tells an operator to go look.
     */
    private <T extends TaxReturnEntity> boolean reencrypt(
            String table, UUID id, Function<UUID, Optional<T>> find, Function<T, T> save) {
        try {
            Optional<T> found = find.apply(id);
            if (found.isEmpty()) {
                // Deleted between the id query and now. Nothing to migrate.
                return false;
            }
            T entity = found.get();
            entity.setFacts(entity.getFacts());
            save.apply(entity);
            return true;
        } catch (Exception e) {
            log.error(
                    "{}: table={}, id={}, {}: {}",
                    FAILURE_MARKER,
                    table,
                    id,
                    e.getClass().getName(),
                    e.getMessage());
            return false;
        }
    }
}
