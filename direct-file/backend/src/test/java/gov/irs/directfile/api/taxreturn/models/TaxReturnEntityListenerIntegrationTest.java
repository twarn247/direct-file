package gov.irs.directfile.api.taxreturn.models;

import java.security.SecureRandom;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.TimeUnit;
import javax.crypto.spec.SecretKeySpec;

import com.amazonaws.encryptionsdk.AwsCrypto;
import com.amazonaws.encryptionsdk.CryptoMaterialsManager;
import com.amazonaws.encryptionsdk.caching.CachingCryptoMaterialsManager;
import com.amazonaws.encryptionsdk.caching.LocalCryptoMaterialsCache;
import com.amazonaws.encryptionsdk.jce.JceMasterKey;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.orm.jpa.TestEntityManager;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Bean;

import gov.irs.directfile.api.config.identity.IdentityAttributes;
import gov.irs.directfile.api.config.identity.IdentitySupplier;
import gov.irs.directfile.api.taxreturn.TaxReturnRepository;
import gov.irs.directfile.api.user.models.User;
import gov.irs.directfile.api.util.base.BaseRepositoryTest;
import gov.irs.directfile.models.FactTypeWithItem;
import gov.irs.directfile.models.autoconfigure.EncryptionContextProperties;
import gov.irs.directfile.models.encryption.DataEncryptDecrypt;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.doReturn;

/**
 * The one test in this codebase that runs TaxReturnEntityListener against a real
 * DataEncryptDecrypt and a real database rather than a mocked encryptor. Exists specifically
 * to prove record=<id> binding against an actual encrypt-then-decrypt round trip -- a mock
 * cannot prove anything about what got bound into a real encryption context.
 */
@ExtendWith(MockitoExtension.class)
class TaxReturnEntityListenerIntegrationTest extends BaseRepositoryTest {

    @TestConfiguration
    static class TestConfig {
        @Bean
        ObjectMapper objectMapper() {
            return new ObjectMapper();
        }

        @Bean
        DataEncryptDecrypt dataEncryptDecrypt() {
            byte[] rawKey = new byte[32];
            new SecureRandom().nextBytes(rawKey);
            JceMasterKey masterKey =
                    JceMasterKey.getInstance(new SecretKeySpec(rawKey, "AES"), "local", "local", "AES/GCM/NoPadding");
            CryptoMaterialsManager cmm = CachingCryptoMaterialsManager.newBuilder()
                    .withMasterKeyProvider(masterKey)
                    .withCache(new LocalCryptoMaterialsCache(10))
                    .withMaxAge(60, TimeUnit.SECONDS)
                    .withMessageUseLimit(1000)
                    .build();
            EncryptionContextProperties properties = new EncryptionContextProperties();
            properties.setContextVerification(EncryptionContextProperties.WARN);
            properties.setRecordContextVerification(EncryptionContextProperties.WARN);
            return new DataEncryptDecrypt(AwsCrypto.standard(), cmm, properties);
        }
    }

    @MockBean
    private IdentitySupplier mockIdentitySupplier;

    @Autowired
    private TestEntityManager entityManager;

    @Autowired
    private TaxReturnRepository taxReturnRepo;

    @BeforeEach
    void configure() {
        doReturn(new IdentityAttributes(UUID.randomUUID(), UUID.randomUUID(), "email@example.com", "123456789"))
                .when(mockIdentitySupplier)
                .get();
    }

    @Test
    void newlyPersistedTaxReturnRoundTripsThroughRealEncryptionWithARecordBinding() {
        // If this fails because taxReturn.getId() was null inside encryptColumns on this
        // first-time insert, the whole premise of binding record=<id> at @PrePersist is wrong
        // -- stop and report rather than adding a null-guard to make this pass.
        User user = new User(UUID.randomUUID());
        entityManager.persist(user);

        TaxReturn taxReturn = new TaxReturn();
        taxReturn.addOwner(user);
        taxReturn.setFacts(Map.of(
                "/foo",
                new FactTypeWithItem(
                        "gov.irs.factgraph.persisters.StringWrapper",
                        com.fasterxml.jackson.databind.node.TextNode.valueOf("baz"))));
        taxReturn.setStore("{}");

        TaxReturn saved = taxReturnRepo.save(taxReturn);
        entityManager.flush();
        entityManager.clear();

        assertThat(saved.getId()).isNotNull();

        // Force a real @PostLoad against what was actually persisted, not the in-memory
        // instance the persistence context would otherwise hand back unchanged. decryptColumns
        // runs here using saved.getId() as the expected record -- if the id were null at
        // @PrePersist, the written record value and this read-time expectation would already
        // disagree, and this would throw EncryptionContextMismatchException before reaching
        // the assertion below.
        TaxReturn reloaded = taxReturnRepo.findById(saved.getId()).orElseThrow();
        assertThat(reloaded.getFacts()).containsKey("/foo");
    }
}
