package gov.irs.directfile.api.taxreturn;

import java.util.Date;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import org.springframework.data.domain.KeysetScrollPosition;
import org.springframework.data.domain.Limit;
import org.springframework.data.domain.ScrollPosition;
import org.springframework.data.domain.Window;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.CrudRepository;
import org.springframework.data.repository.query.Param;

import gov.irs.directfile.api.taxreturn.models.TaxReturn;

public interface TaxReturnRepository extends CrudRepository<TaxReturn, UUID> {
    @Query("SELECT t FROM TaxReturn t JOIN t.owners o WHERE o.id = :userId ORDER BY t.taxYear DESC")
    List<TaxReturn> findByUserId(UUID userId);

    @Query("SELECT t FROM TaxReturn t JOIN t.owners o WHERE o.id = :userId AND t.id = :id")
    Optional<TaxReturn> findByIdAndUserId(UUID id, UUID userId);

    @Query("SELECT t FROM TaxReturn t JOIN t.owners o WHERE o.id = :userId AND t.taxYear = :taxYear")
    Optional<TaxReturn> findByUserIdAndTaxYear(UUID userId, int taxYear);

    @Query(value = "SELECT t FROM TaxReturn t WHERE t.id in :taxReturnIds")
    List<TaxReturn> findAllByTaxReturnIds(List<UUID> taxReturnIds);

    // Based on Spring Query Method Docs:
    // https://docs.spring.io/spring-data/jpa/reference/repositories/query-methods-details.html
    Window<TaxReturn> findByTaxYearAndCreatedAtBetweenOrderByCreatedAtAsc(
            Limit limit, ScrollPosition scrollPosition, int taxYear, Date createdStart, Date createdEnd);

    // Scrolling Reference Docs:
    // https://docs.spring.io/spring-data/jpa/reference/data-commons/repositories/scrolling.html#repositories.scrolling.keyset
    // Query Method Docs:
    // https://docs.spring.io/spring-data/jpa/docs/current-SNAPSHOT/reference/html/#jpa.query-methods.query-creation
    Window<SimpleTaxReturnProjection> findByTaxYearAndSubmitTimeIsNullAndCreatedAtBetweenOrderByCreatedAtAsc(
            Limit limit, int taxYear, Date createdStart, Date createdEnd, KeysetScrollPosition position);

    /**
     * Primary keys for the H-1 Phase B backfill, ascending, strictly greater than
     * {@code afterId}. Pass the all-zero UUID to start from the beginning.
     *
     * <p>Returns ids rather than entities on purpose: loading entities fires @PostLoad,
     * which decrypts every row in the page, so one undecryptable row would fail the whole
     * page and stall the sweep permanently. The backfill loads each row individually.
     */
    @Query("SELECT t.id FROM TaxReturn t WHERE t.id > :afterId ORDER BY t.id ASC")
    List<UUID> findIdsForBackfillAfter(@Param("afterId") UUID afterId, Limit limit);
}
