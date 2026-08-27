package gov.irs.directfile.api.taxreturn;

import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;

import gov.irs.directfile.api.taxreturn.models.EncryptionBackfillProgress;

@Repository
public interface EncryptionBackfillProgressRepository extends CrudRepository<EncryptionBackfillProgress, String> {}
