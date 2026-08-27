package gov.irs.directfile.api.taxreturn;

import java.util.Optional;
import java.util.UUID;
import java.util.function.Function;

import jakarta.persistence.EntityManager;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.interceptor.TransactionAspectSupport;
import org.springframework.transaction.support.TransactionSynchronizationManager;

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
    private final EntityManager entityManager;

    public EncryptionBackfillRowService(
            TaxReturnRepository taxReturnRepository,
            TaxReturnSubmissionRepository taxReturnSubmissionRepository,
            EntityManager entityManager) {
        this.taxReturnRepository = taxReturnRepository;
        this.taxReturnSubmissionRepository = taxReturnSubmissionRepository;
        this.entityManager = entityManager;
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
     *
     * <p>{@code save.apply(entity)} alone does not flush: with an entity already managed by
     * this transaction's persistence context, {@code save} is a no-op that returns the same
     * managed instance, and {@code @PreUpdate}'s re-encryption only actually runs when the
     * persistence context flushes, which otherwise happens at this method's transaction
     * commit — after this try/catch has already returned. An explicit {@link
     * EntityManager#flush()} inside the try forces that re-encryption to happen here, so an
     * encryption failure at write time is caught by the same catch block as a decrypt failure
     * at read time, rather than escaping to the caller uncaught.
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
            entityManager.flush();
            return true;
        } catch (Exception e) {
            log.error(
                    "{}: table={}, id={}, {}: {}",
                    FAILURE_MARKER,
                    table,
                    id,
                    e.getClass().getName(),
                    e.getMessage());
            // The flush may have already left this transaction's persistence context
            // unusable. Marking rollback-only tells the REQUIRES_NEW proxy to roll back
            // rather than attempt a commit that would throw past this catch block. Guarded
            // for unit tests, which call this method directly and have no live transaction.
            if (TransactionSynchronizationManager.isActualTransactionActive()) {
                TransactionAspectSupport.currentTransactionStatus().setRollbackOnly();
            }
            return false;
        }
    }
}
