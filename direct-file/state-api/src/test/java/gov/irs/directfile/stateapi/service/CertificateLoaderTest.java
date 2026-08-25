package gov.irs.directfile.stateapi.service;

import java.io.FileInputStream;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.test.context.ActiveProfiles;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import gov.irs.directfile.stateapi.repository.StateApiS3Client;

import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

// @Cacheable and @CacheEvict work through a Spring AOP proxy, so a plain Mockito unit
// test (constructing CertificateLoader directly) cannot exercise real caching or
// eviction behavior. This uses a real Spring context, same pattern as
// CachedDataServiceConfigurationTest: @SpringBootTests are expensive and should be
// used extremely sparingly, but eviction is specifically a cross-cutting-proxy
// behavior that a unit test cannot observe.
@SpringBootTest
@ActiveProfiles("test")
public class CertificateLoaderTest {

    private static final String CERT_NAME = "unexpired.cer";
    private static final String CERT_PATH = "src/test/resources/certificates/unexpired.cer";

    @MockBean
    private StateApiS3Client s3Client;

    @Autowired
    private CertificateLoader certificateLoader;

    @Test
    public void evictCertificate_forcesTheNextLoadToGoBackToS3() throws Exception {
        when(s3Client.getCert(CERT_NAME)).thenAnswer(invocation -> Mono.just(new FileInputStream(CERT_PATH)));

        // First load populates the cache.
        StepVerifier.create(certificateLoader.loadCertificate(CERT_NAME))
                .expectNextCount(1)
                .verifyComplete();

        // Second load is served from the cache: no additional S3 call.
        StepVerifier.create(certificateLoader.loadCertificate(CERT_NAME))
                .expectNextCount(1)
                .verifyComplete();
        verify(s3Client, times(1)).getCert(CERT_NAME);

        // Evict, then load again: this must genuinely go back to S3, not just avoid
        // throwing.
        certificateLoader.evictCertificate(CERT_NAME);

        StepVerifier.create(certificateLoader.loadCertificate(CERT_NAME))
                .expectNextCount(1)
                .verifyComplete();
        verify(s3Client, times(2)).getCert(CERT_NAME);
    }
}
