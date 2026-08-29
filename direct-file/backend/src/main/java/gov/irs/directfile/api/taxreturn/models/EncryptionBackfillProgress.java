package gov.irs.directfile.api.taxreturn.models;

import java.util.Date;
import java.util.UUID;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.Getter;
import lombok.Setter;
import org.hibernate.annotations.UpdateTimestamp;

/**
 * Resume point for the H-1 Phase B ciphertext backfill, one row per target table.
 *
 * <p>Deliberately a persisted cursor rather than an in-memory scroll position: a
 * full-table pass over encrypted data will be interrupted by deploys and restarts, and
 * restarting from the beginning each time would never finish on a large table.
 */
@Entity
@Table(name = "encryption_backfill_progress")
@Getter
@Setter
public class EncryptionBackfillProgress {

    public static final String TAX_RETURNS = "taxreturns";
    public static final String TAX_RETURN_SUBMISSIONS = "taxreturn_submissions";

    @Id
    @Column(name = "target_table", nullable = false)
    private String targetTable;

    /** Highest primary key already re-encrypted. Null means the sweep has not started. */
    @Column(name = "last_id")
    private UUID lastId;

    @Column(name = "completed", nullable = false)
    private boolean completed;

    @UpdateTimestamp
    @Column(name = "updated_at", nullable = false)
    private Date updatedAt;
}
