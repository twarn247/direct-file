package gov.irs.directfile.api.taxreturn;

import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;

import gov.irs.directfile.api.taxreturn.models.EncryptionBackfillProgress;

@Repository
public interface EncryptionBackfillProgressRepository extends CrudRepository<EncryptionBackfillProgress, String> {

    /**
     * The precondition for flipping an encryption-context-verification flag from warn to
     * enforce: every persisted progress row finished its sweep, and not one of them left a
     * single row unmigrated. False if even one row is still in progress or ended with any
     * failures at all. Checkable with one query rather than a log search whose answer
     * depends on retention outliving the sweep.
     */
    @Query("SELECT COUNT(p) = 0 FROM EncryptionBackfillProgress p WHERE p.completed = false OR p.failed > 0")
    boolean allTablesCleanlyMigrated();
}
