package gov.irs.directfile.stateapi.service;

import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import lombok.extern.slf4j.Slf4j;
import org.springframework.cache.annotation.CacheEvict;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

import gov.irs.directfile.error.StateApiErrorCode;
import gov.irs.directfile.stateapi.exception.StateApiException;
import gov.irs.directfile.stateapi.repository.StateApiS3Client;

/**
 * Fetches and parses state certificates from S3.
 *
 * Deliberately a separate bean from CachedDataService: @Cacheable works through a
 * Spring proxy, and a self-invocation from another method on the same bean bypasses
 * the proxy and silently disables caching. Keeping the cached parse here lets
 * CachedDataService evaluate expiration on every call while still avoiding an S3
 * round trip per export.
 *
 * This class performs NO expiration checking. That is CachedDataService's job, and it
 * must stay outside the cache.
 */
@Component
@Slf4j
@SuppressWarnings("PMD.PreserveStackTrace")
public class CertificateLoader {

    private final StateApiS3Client s3Client;

    public CertificateLoader(StateApiS3Client s3Client) {
        this.s3Client = s3Client;
    }

    @Cacheable(cacheNames = "certificateCache", key = "#certName")
    public Mono<X509Certificate> loadCertificate(String certName) {
        log.info("enter loadCertificate()...for {}", certName);

        return s3Client.getCert(certName)
                .flatMap(is -> {
                    try {
                        CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
                        return Mono.just((X509Certificate) certFactory.generateCertificate(is));
                    } catch (CertificateException e) {
                        log.error("loadCertificate failed, {}, {}", e.getClass().getName(), e.getMessage());
                        return Mono.error(new StateApiException(StateApiErrorCode.E_INTERNAL_SERVER_ERROR));
                    }
                })
                .cache(); // required for @Cacheable over a Mono
    }

    /**
     * Evicts one certificate by name from the cache. This is the targeted revocation
     * path: replacing the S3 object alone does nothing until the cache TTL expires
     * (spring.cache.TTL-minutes, default 120) or this is called for that certName.
     */
    @CacheEvict(cacheNames = "certificateCache", key = "#certName")
    public void evictCertificate(String certName) {
        log.info("evicted certificate {} from certificateCache", certName);
    }
}
