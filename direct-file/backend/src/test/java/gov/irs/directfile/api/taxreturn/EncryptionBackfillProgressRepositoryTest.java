package gov.irs.directfile.api.taxreturn;

import java.util.Optional;
import java.util.UUID;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.orm.jpa.TestEntityManager;

import gov.irs.directfile.api.taxreturn.models.EncryptionBackfillProgress;
import gov.irs.directfile.api.util.base.BaseRepositoryTest;

import static org.assertj.core.api.Assertions.assertThat;

@ExtendWith(MockitoExtension.class)
class EncryptionBackfillProgressRepositoryTest extends BaseRepositoryTest {

    @Autowired
    private EncryptionBackfillProgressRepository repository;

    @Autowired
    private TestEntityManager entityManager;

    @Test
    void persistsAndReadsBackACursor() {
        UUID cursor = UUID.randomUUID();
        EncryptionBackfillProgress progress = new EncryptionBackfillProgress();
        progress.setTargetTable(EncryptionBackfillProgress.TAX_RETURNS);
        progress.setLastId(cursor);
        progress.setCompleted(false);

        repository.save(progress);
        // Force a real round trip to the database (flush the pending INSERT, then clear
        // the persistence context) so findById below actually validates the migration's
        // column mapping instead of being served from the first-level cache.
        entityManager.flush();
        entityManager.clear();

        Optional<EncryptionBackfillProgress> found = repository.findById(EncryptionBackfillProgress.TAX_RETURNS);
        assertThat(found).isPresent();
        assertThat(found.get().getLastId()).isEqualTo(cursor);
        assertThat(found.get().isCompleted()).isFalse();
    }

    @Test
    void tracksTheTwoTablesIndependently() {
        UUID returnsCursor = UUID.randomUUID();
        UUID submissionsCursor = UUID.randomUUID();

        EncryptionBackfillProgress returns = new EncryptionBackfillProgress();
        returns.setTargetTable(EncryptionBackfillProgress.TAX_RETURNS);
        returns.setLastId(returnsCursor);

        EncryptionBackfillProgress submissions = new EncryptionBackfillProgress();
        submissions.setTargetTable(EncryptionBackfillProgress.TAX_RETURN_SUBMISSIONS);
        submissions.setLastId(submissionsCursor);
        submissions.setCompleted(true);

        repository.saveAll(java.util.List.of(returns, submissions));
        entityManager.flush();
        entityManager.clear();

        assertThat(repository
                        .findById(EncryptionBackfillProgress.TAX_RETURNS)
                        .orElseThrow()
                        .getLastId())
                .isEqualTo(returnsCursor);
        assertThat(repository
                        .findById(EncryptionBackfillProgress.TAX_RETURN_SUBMISSIONS)
                        .orElseThrow()
                        .isCompleted())
                .isTrue();
    }

    @Test
    void allTablesCleanlyMigrated_isFalseWhenAnyTableIsIncomplete() {
        EncryptionBackfillProgress incomplete = new EncryptionBackfillProgress();
        incomplete.setTargetTable(EncryptionBackfillProgress.TAX_RETURNS);
        incomplete.setCompleted(false);
        repository.save(incomplete);

        assertThat(repository.allTablesCleanlyMigrated()).isFalse();
    }

    @Test
    void allTablesCleanlyMigrated_isFalseWhenACompletedTableHasFailures() {
        EncryptionBackfillProgress completedWithFailures = new EncryptionBackfillProgress();
        completedWithFailures.setTargetTable(EncryptionBackfillProgress.TAX_RETURNS);
        completedWithFailures.setCompleted(true);
        completedWithFailures.setFailed(1);
        repository.save(completedWithFailures);

        assertThat(repository.allTablesCleanlyMigrated()).isFalse();
    }

    @Test
    void allTablesCleanlyMigrated_isFalseWhenNoRowsExistAtAll() {
        // The default state: the backfill ships disabled and has never run, so this table is
        // empty on every deployment. "No bad row exists" would be vacuously true here -- the
        // defect this test guards against.
        assertThat(repository.allTablesCleanlyMigrated()).isFalse();
    }

    @Test
    void allTablesCleanlyMigrated_isFalseWhenOnlyOneOfTwoTablesIsClean() {
        EncryptionBackfillProgress onlyReturns = new EncryptionBackfillProgress();
        onlyReturns.setTargetTable(EncryptionBackfillProgress.TAX_RETURNS);
        onlyReturns.setCompleted(true);
        onlyReturns.setFailed(0);
        repository.save(onlyReturns);
        // taxreturn_submissions is never saved -- untouched, not just incomplete.

        assertThat(repository.allTablesCleanlyMigrated()).isFalse();
    }

    @Test
    void allTablesCleanlyMigrated_isTrueWhenEveryTableFinishedWithZeroFailures() {
        EncryptionBackfillProgress returns = new EncryptionBackfillProgress();
        returns.setTargetTable(EncryptionBackfillProgress.TAX_RETURNS);
        returns.setCompleted(true);
        returns.setFailed(0);

        EncryptionBackfillProgress submissions = new EncryptionBackfillProgress();
        submissions.setTargetTable(EncryptionBackfillProgress.TAX_RETURN_SUBMISSIONS);
        submissions.setCompleted(true);
        submissions.setFailed(0);

        repository.saveAll(java.util.List.of(returns, submissions));

        assertThat(repository.allTablesCleanlyMigrated()).isTrue();
    }
}
