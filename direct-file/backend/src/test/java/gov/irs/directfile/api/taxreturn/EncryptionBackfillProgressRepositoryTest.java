package gov.irs.directfile.api.taxreturn;

import java.util.Optional;
import java.util.UUID;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.beans.factory.annotation.Autowired;

import gov.irs.directfile.api.taxreturn.models.EncryptionBackfillProgress;
import gov.irs.directfile.api.util.base.BaseRepositoryTest;

import static org.assertj.core.api.Assertions.assertThat;

@ExtendWith(MockitoExtension.class)
class EncryptionBackfillProgressRepositoryTest extends BaseRepositoryTest {

    @Autowired
    private EncryptionBackfillProgressRepository repository;

    @Test
    void persistsAndReadsBackACursor() {
        UUID cursor = UUID.randomUUID();
        EncryptionBackfillProgress progress = new EncryptionBackfillProgress();
        progress.setTargetTable(EncryptionBackfillProgress.TAX_RETURNS);
        progress.setLastId(cursor);
        progress.setCompleted(false);

        repository.save(progress);

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
}
