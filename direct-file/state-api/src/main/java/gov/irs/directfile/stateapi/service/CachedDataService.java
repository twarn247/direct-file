package gov.irs.directfile.stateapi.service;

import java.security.PublicKey;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.Date;
import java.util.List;
import java.util.concurrent.TimeUnit;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cache.annotation.CacheEvict;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

import gov.irs.directfile.error.StateApiErrorCode;
import gov.irs.directfile.stateapi.dto.StateProfileDTO;
import gov.irs.directfile.stateapi.exception.StateApiException;
import gov.irs.directfile.stateapi.exception.StateNotExistException;
import gov.irs.directfile.stateapi.model.StateLanguage;
import gov.irs.directfile.stateapi.model.StateProfile;
import gov.irs.directfile.stateapi.model.StateRedirect;
import gov.irs.directfile.stateapi.repository.StateLanguageRepository;
import gov.irs.directfile.stateapi.repository.StateProfileRepository;
import gov.irs.directfile.stateapi.repository.StateRedirectRepository;

@Component
@Slf4j
@SuppressWarnings("PMD.PreserveStackTrace")
public class CachedDataService {
    @Autowired
    private CertificateLoader certificateLoader;

    @Autowired
    private StateProfileRepository spRepo;

    @Autowired
    private StateRedirectRepository srRepo;

    @Autowired
    private StateLanguageRepository slRepo;

    @Value("${spring.cache.TTL-minutes: 120}")
    private long cacheTTL;

    // Note: We are applying cache of cache to a Mono. The native Caffeine cache's 'expireAfterAccess' won't take
    // effect. For the sake of simplicity, we periodically evict the caches.
    @CacheEvict(
            value = {"certificateCache", "stateProfileCache"},
            allEntries = true)
    @Scheduled(fixedRateString = "${spring.cache.TTL-minutes}", timeUnit = TimeUnit.MINUTES)
    public void emptyCaches() {
        log.info("caches (certificateCache, stateProfileCache) were evicted after {} minutes", cacheTTL);
    }

    /**
     * Resolves a state's public key.
     *
     * The parsed certificate is cached (CertificateLoader); the expiration checks are
     * NOT. Both the certificate's own notAfter and the IRS-enforced expiration date are
     * evaluated on every call, so administratively expiring a compromised certificate
     * takes effect immediately rather than after the cache TTL.
     */
    public Mono<PublicKey> retrievePublicKeyFromCert(String certName, OffsetDateTime enforcedExpirationDate) {
        log.info("enter retrievePublicKeyFromCert()...for {}", certName);

        return certificateLoader.loadCertificate(certName).map(cert -> {
            Date currentDate = new Date();
            if (currentDate.after(cert.getNotAfter())) {
                log.error("The certificate {} has expired", certName);
                throw new StateApiException(StateApiErrorCode.E_CERTIFICATE_EXPIRED);
            }

            if (enforcedExpirationDate != null) {
                OffsetDateTime currentDateTime = OffsetDateTime.now(ZoneOffset.UTC);
                if (currentDateTime.isAfter(enforcedExpirationDate)) {
                    log.error("The certificate {} has passed the IRS enforced expiration date", certName);
                    throw new StateApiException(StateApiErrorCode.E_CERTIFICATE_EXPIRED);
                }
            }

            return cert.getPublicKey();
        });
    }

    @Cacheable(cacheNames = "stateProfileCache", key = "#accountId")
    public Mono<StateProfile> getStateProfile(String accountId) {
        log.info("enter getStateProfile()...accountId={}", accountId);

        return spRepo.getByAccountId(accountId)
                .switchIfEmpty(Mono.defer(() -> {
                    log.error(
                            "getStateProfile() failed, account id does not exist in state_profile table for account id: {}",
                            accountId);
                    return Mono.error(new StateApiException(StateApiErrorCode.E_ACCOUNT_ID_NOT_EXIST));
                }))
                .onErrorMap(e -> !(e instanceof StateApiException), e -> {
                    log.error(
                            "getStateProfile failed for account id: {}, {}, error: {}",
                            accountId,
                            e.getClass().getName(),
                            e.getMessage());
                    return new StateApiException(StateApiErrorCode.E_INTERNAL_SERVER_ERROR);
                })
                .cache();
    }

    @Cacheable(cacheNames = "stateProfileCache", key = "#stateCode")
    public Mono<StateProfileDTO> getStateProfileByStateCode(String stateCode) {
        log.info("enter getStateProfileByStateCode()...stateCode={}", stateCode);

        return spRepo.getByStateCode(stateCode)
                .flatMap(this::loadRelations)
                .switchIfEmpty(Mono.defer(() -> {
                    log.info("No StateProfile returns, state code {} does not exist in state_profile table", stateCode);
                    return Mono.error(new StateNotExistException(StateApiErrorCode.E_STATE_NOT_EXIST));
                }))
                .onErrorMap(e -> !(e instanceof StateApiException), e -> {
                    log.error(
                            "getStateProfileByStateCode() failed for state code: {}, {}, error: {}",
                            stateCode,
                            e.getClass().getName(),
                            e.getMessage());

                    return new StateApiException(StateApiErrorCode.E_INTERNAL_SERVER_ERROR);
                })
                .cache();
    }

    private Mono<StateProfileDTO> loadRelations(final StateProfile stateProfile) {
        var stateProfileId = stateProfile.getId();

        // Load the redirect urls
        Mono<List<StateRedirect>> redirectUrls =
                srRepo.getAllByStateProfileId(stateProfileId).collectList();
        // Load the languages
        Mono<List<StateLanguage>> stateLanguages =
                slRepo.getAllByStateProfileId(stateProfileId).collectList();

        return redirectUrls
                .zipWith(stateLanguages)
                .map((urlsAndLanguagesTuple) -> new StateProfileDTO(
                        stateProfile, urlsAndLanguagesTuple.getT1(), urlsAndLanguagesTuple.getT2()));
    }
}
