package gov.irs.directfile.stateapi.repository;

import org.springframework.data.r2dbc.repository.Modifying;
import org.springframework.data.r2dbc.repository.Query;
import org.springframework.data.r2dbc.repository.R2dbcRepository;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;
import reactor.core.publisher.Mono;

import gov.irs.directfile.stateapi.model.AuthorizationCode;

@Repository
public interface AuthorizationCodeRepository extends R2dbcRepository<AuthorizationCode, Integer> {
    Mono<AuthorizationCode> getByAuthorizationCode(@Param("authorizationCode") String authDigest);

    /**
     * Atomically marks a code redeemed. Returns the number of rows updated: 1 when this
     * caller won the redemption, 0 when the code was already redeemed or does not exist.
     *
     * The conditional WHERE is the concurrency control — a read-then-write would let two
     * simultaneous exports both succeed.
     */
    @Modifying
    @Query("UPDATE authorization_code SET redeemed_at = now() "
            + "WHERE authorization_code = :authDigest AND redeemed_at IS NULL")
    Mono<Integer> markRedeemed(@Param("authDigest") String authDigest);
}
