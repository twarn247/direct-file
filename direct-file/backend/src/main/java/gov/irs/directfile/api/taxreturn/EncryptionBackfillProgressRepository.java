package gov.irs.directfile.api.taxreturn;

import java.util.List;
import java.util.Set;

import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.CrudRepository;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import gov.irs.directfile.api.taxreturn.models.EncryptionBackfillProgress;

@Repository
public interface EncryptionBackfillProgressRepository extends CrudRepository<EncryptionBackfillProgress, String> {

    /**
     * Every target table this backfill covers. Not derived from the table itself: a row only
     * exists once {@code processNextBatch} has actually run for it (see {@code orElseGet} in
     * {@code EncryptionBackfillService}), so a table this sweep has never touched has no row
     * at all -- counting distinct persisted {@code target_table} values would silently treat
     * "never started" the same as "not one of ours."
     */
    List<String> KNOWN_TARGET_TABLES =
            List.of(EncryptionBackfillProgress.TAX_RETURNS, EncryptionBackfillProgress.TAX_RETURN_SUBMISSIONS);

    @Query("SELECT COUNT(p) FROM EncryptionBackfillProgress p "
            + "WHERE p.targetTable IN :targetTables AND p.completed = true AND p.failed = 0")
    long countCleanlyMigrated(@Param("targetTables") Set<String> targetTables);

    /**
     * The precondition for flipping an encryption-context-verification flag from warn to
     * enforce: every known target table has a persisted row, that row finished its sweep, and
     * not one row it touched failed. Checkable with one query rather than a log search whose
     * answer depends on retention outliving the sweep.
     *
     * <p>Deliberately not "no bad row exists": a table with no persisted row at all -- the
     * default state, since the backfill ships disabled and this table starts empty on every
     * deployment -- has zero bad rows and would satisfy that phrasing vacuously, answering
     * true for "nothing has migrated" the same as for "everything migrated cleanly." This
     * counts rows that are actually clean and requires that count to cover every known table,
     * so an empty table or a table this sweep has not reached yet both correctly answer false.
     */
    default boolean allTablesCleanlyMigrated() {
        return countCleanlyMigrated(Set.copyOf(KNOWN_TARGET_TABLES)) == KNOWN_TARGET_TABLES.size();
    }
}
