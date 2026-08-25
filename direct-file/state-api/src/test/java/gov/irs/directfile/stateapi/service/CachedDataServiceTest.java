package gov.irs.directfile.stateapi.service;

import java.io.FileInputStream;
import java.io.InputStream;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.dao.DataAccessException;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import gov.irs.directfile.error.StateApiErrorCode;
import gov.irs.directfile.stateapi.exception.StateApiException;
import gov.irs.directfile.stateapi.exception.StateNotExistException;
import gov.irs.directfile.stateapi.model.StateProfile;
import gov.irs.directfile.stateapi.model.StateRedirect;
import gov.irs.directfile.stateapi.repository.StateLanguageRepository;
import gov.irs.directfile.stateapi.repository.StateProfileRepository;
import gov.irs.directfile.stateapi.repository.StateRedirectRepository;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
public class CachedDataServiceTest {

    @InjectMocks
    private CachedDataService cachedDS;

    @Mock
    private CertificateLoader certificateLoader;

    @Mock
    private StateProfileRepository spRepo;

    @Mock
    private StateRedirectRepository srRepo;

    @Mock
    private StateLanguageRepository slRepo;

    @Test
    public void testRetrievePublicKeyFromCert_Success() throws Exception {
        X509Certificate validCert = loadFixtureCertificate("unexpired.cer");
        when(certificateLoader.loadCertificate("cert-name")).thenReturn(Mono.just(validCert));

        var resultMono = cachedDS.retrievePublicKeyFromCert("cert-name", null);

        StepVerifier.create(resultMono)
                .expectNextMatches(pk -> pk.getFormat().equals("X.509"))
                .verifyComplete();
    }

    @Test
    public void testRetrievePublicKeyFromCert_CertExpired() throws Exception {
        X509Certificate validCert = loadFixtureCertificate("unexpired.cer");
        OffsetDateTime expireDateTime = OffsetDateTime.of(2023, 1, 1, 1, 1, 1, 1, ZoneOffset.UTC);

        when(certificateLoader.loadCertificate("cert-name")).thenReturn(Mono.just(validCert));

        var resultMono = cachedDS.retrievePublicKeyFromCert("cert-name", expireDateTime);

        StepVerifier.create(resultMono)
                .expectErrorMatches(
                        e -> e instanceof StateApiException && e.getMessage().equals("E_CERTIFICATE_EXPIRED"))
                .verify();
    }

    @Test
    public void retrievePublicKeyFromCert_rejectsWhenEnforcedDateHasPassed() throws Exception {
        X509Certificate validCert = loadFixtureCertificate("unexpired.cer");
        when(certificateLoader.loadCertificate("fakestate.cer")).thenReturn(Mono.just(validCert));

        OffsetDateTime enforcedInThePast = OffsetDateTime.now(ZoneOffset.UTC).minusDays(1);

        StepVerifier.create(cachedDS.retrievePublicKeyFromCert("fakestate.cer", enforcedInThePast))
                .expectErrorMatches(e -> e instanceof StateApiException sae
                        && sae.getErrorCode() == StateApiErrorCode.E_CERTIFICATE_EXPIRED)
                .verify();
    }

    @Test
    public void retrievePublicKeyFromCert_reevaluatesEnforcedDateOnEveryCall() throws Exception {
        X509Certificate validCert = loadFixtureCertificate("unexpired.cer");
        when(certificateLoader.loadCertificate("fakestate.cer")).thenReturn(Mono.just(validCert));

        OffsetDateTime future = OffsetDateTime.now(ZoneOffset.UTC).plusDays(1);
        OffsetDateTime past = OffsetDateTime.now(ZoneOffset.UTC).minusDays(1);

        // First call succeeds with a future enforced date.
        StepVerifier.create(cachedDS.retrievePublicKeyFromCert("fakestate.cer", future))
                .assertNext(key -> assertThat(key).isNotNull())
                .verifyComplete();

        // Second call with a past enforced date must fail even though the certificate
        // itself is cached. This is the regression this task exists to prevent.
        StepVerifier.create(cachedDS.retrievePublicKeyFromCert("fakestate.cer", past))
                .expectErrorMatches(e -> e instanceof StateApiException sae
                        && sae.getErrorCode() == StateApiErrorCode.E_CERTIFICATE_EXPIRED)
                .verify();
    }

    @Test
    public void retrievePublicKeyFromCert_returnsKeyWhenBothDatesAreInTheFuture() throws Exception {
        X509Certificate validCert = loadFixtureCertificate("unexpired.cer");
        when(certificateLoader.loadCertificate("fakestate.cer")).thenReturn(Mono.just(validCert));

        StepVerifier.create(cachedDS.retrievePublicKeyFromCert(
                        "fakestate.cer", OffsetDateTime.now(ZoneOffset.UTC).plusDays(1)))
                .assertNext(key -> assertThat(key).isNotNull())
                .verifyComplete();
    }

    private X509Certificate loadFixtureCertificate(String name) throws Exception {
        try (InputStream is = new FileInputStream("src/test/resources/certificates/" + name)) {
            return (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(is);
        }
    }

    @Test
    public void testGetStateProfileByStateCode_Success() throws Exception {
        String stateCode = "FS";
        StateProfile stateProfile = new StateProfile();
        stateProfile.setId(1L);
        stateProfile.setStateCode("FS");
        stateProfile.setTaxSystemName("taxsysname");
        stateProfile.setDepartmentOfRevenueUrl("url");
        stateProfile.setFilingRequirementsUrl("url");

        List<StateRedirect> mockStateRedirectList = new ArrayList<>();
        var sr1 = new StateRedirect();
        sr1.setRedirectUrl("http://the-url1");
        mockStateRedirectList.add(sr1);
        var sr2 = new StateRedirect();
        sr2.setRedirectUrl("http://the-url2");
        mockStateRedirectList.add(sr2);

        when(spRepo.getByStateCode(stateCode)).thenReturn(Mono.just(stateProfile));
        when(srRepo.getAllByStateProfileId(1L)).thenReturn(Flux.fromIterable(mockStateRedirectList));
        when(slRepo.getAllByStateProfileId(1L)).thenReturn(Flux.fromIterable(new ArrayList<>()));

        var resultMono = cachedDS.getStateProfileByStateCode(stateCode);

        StepVerifier.create(resultMono)
                .expectNextMatches(sp -> sp.taxSystemName().equals("taxsysname")
                        && "url".equals(sp.departmentOfRevenueUrl())
                        && "url".equals(sp.filingRequirementsUrl()))
                .verifyComplete();
    }

    @Test
    public void testGetStateProfileByStateCode_StateNotExist() throws Exception {
        String stateCode = "FS";

        when(spRepo.getByStateCode(stateCode)).thenReturn(Mono.empty());

        var resultMono = cachedDS.getStateProfileByStateCode(stateCode);

        StepVerifier.create(resultMono)
                .expectErrorMatches(e ->
                        e instanceof StateNotExistException && e.getMessage().contains("E_STATE_NOT_EXIST"))
                .verify();
    }

    @Test
    public void testGetStateProfileByStateCode_Exception() {
        String stateCode = "FS";

        when(spRepo.getByStateCode(stateCode)).thenReturn(Mono.error(new DataAccessException("error") {}));

        var resultMono = cachedDS.getStateProfileByStateCode(stateCode);

        StepVerifier.create(resultMono)
                .expectErrorMatches(
                        e -> e instanceof StateApiException && e.getMessage().equals("E_INTERNAL_SERVER_ERROR"))
                .verify();
    }

    @Test
    public void testGetStateProfile_Success() {
        String accountId = "123456";
        StateProfile stateProfile = new StateProfile();
        stateProfile.setStateCode("FS");

        when(spRepo.getByAccountId(accountId)).thenReturn(Mono.just(stateProfile));

        var resultMono = cachedDS.getStateProfile(accountId);

        StepVerifier.create(resultMono)
                .expectNextMatches(sp -> sp.getStateCode().equals("FS"))
                .verifyComplete();
    }

    @Test
    public void testGetStateProfile_AccountIDNotExist() {
        String accountId = "123456";
        StateProfile stateProfile = new StateProfile();
        stateProfile.setStateCode("FS");

        when(spRepo.getByAccountId(accountId)).thenReturn(Mono.empty());

        var resultMono = cachedDS.getStateProfile(accountId);

        StepVerifier.create(resultMono)
                .expectErrorMatches(
                        e -> e instanceof StateApiException && e.getMessage().equals("E_ACCOUNT_ID_NOT_EXIST"))
                .verify();
    }

    @Test
    public void testGetStateProfile_Exception() {
        String accountId = "123456";
        StateProfile stateProfile = new StateProfile();
        stateProfile.setStateCode("FS");

        when(spRepo.getByAccountId(accountId)).thenReturn(Mono.error(new DataAccessException("error") {}));

        var resultMono = cachedDS.getStateProfile(accountId);

        StepVerifier.create(resultMono)
                .expectErrorMatches(
                        e -> e instanceof StateApiException && e.getMessage().equals("E_INTERNAL_SERVER_ERROR"))
                .verify();
    }
}
