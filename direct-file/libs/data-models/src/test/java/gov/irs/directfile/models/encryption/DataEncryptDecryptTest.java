package gov.irs.directfile.models.encryption;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.concurrent.TimeUnit;
import javax.crypto.spec.SecretKeySpec;

import com.amazonaws.encryptionsdk.AwsCrypto;
import com.amazonaws.encryptionsdk.CryptoMaterialsManager;
import com.amazonaws.encryptionsdk.caching.CachingCryptoMaterialsManager;
import com.amazonaws.encryptionsdk.caching.LocalCryptoMaterialsCache;
import com.amazonaws.encryptionsdk.jce.JceMasterKey;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import gov.irs.directfile.models.autoconfigure.EncryptionContextProperties;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

public class DataEncryptDecryptTest {
    private static final byte[] PLAINTEXT = "some plaintext".getBytes(StandardCharsets.UTF_8);

    private CryptoMaterialsManager cmm;
    private AwsCrypto awsCrypto;

    @BeforeEach
    void setUp() {
        byte[] rawKey = new byte[32];
        new SecureRandom().nextBytes(rawKey);
        JceMasterKey masterKey =
                JceMasterKey.getInstance(new SecretKeySpec(rawKey, "AES"), "local", "local", "AES/GCM/NoPadding");
        cmm = CachingCryptoMaterialsManager.newBuilder()
                .withMasterKeyProvider(masterKey)
                .withCache(new LocalCryptoMaterialsCache(10))
                .withMaxAge(60, TimeUnit.SECONDS)
                .withMessageUseLimit(1000)
                .build();
        awsCrypto = AwsCrypto.standard();
    }

    private DataEncryptDecrypt subject(String mode) {
        EncryptionContextProperties properties = new EncryptionContextProperties();
        properties.setContextVerification(mode);
        return new DataEncryptDecrypt(awsCrypto, cmm, properties);
    }

    @Test
    void roundTripsUnderMatchingPurpose() {
        DataEncryptDecrypt subject = subject("warn");
        byte[] ciphertext = subject.encrypt(PLAINTEXT, EncryptionPurpose.TAX_RETURN_FACTS, null);
        assertThat(subject.decrypt(ciphertext, EncryptionPurpose.TAX_RETURN_FACTS))
                .isEqualTo(PLAINTEXT);
    }

    @Test
    void rejectsAStoreBlobPresentedAsFacts_inWarnMode() {
        // The substitution the finding is about. Rejected regardless of mode.
        DataEncryptDecrypt subject = subject("warn");
        byte[] ciphertext = subject.encrypt(PLAINTEXT, EncryptionPurpose.TAX_RETURN_STORE, null);
        assertThatThrownBy(() -> subject.decrypt(ciphertext, EncryptionPurpose.TAX_RETURN_FACTS))
                .isInstanceOf(EncryptionContextMismatchException.class);
    }

    @Test
    void rejectsAStateExportTokenPresentedAsFacts() {
        DataEncryptDecrypt subject = subject("warn");
        byte[] ciphertext = subject.encrypt(PLAINTEXT, EncryptionPurpose.STATE_EXPORT_TOKEN, null);
        assertThatThrownBy(() -> subject.decrypt(ciphertext, EncryptionPurpose.TAX_RETURN_FACTS))
                .isInstanceOf(EncryptionContextMismatchException.class);
    }

    @Test
    void acceptsLegacyUntaggedCiphertext_inWarnMode() {
        DataEncryptDecrypt subject = subject("warn");
        byte[] legacy = awsCrypto
                .encryptData(cmm, PLAINTEXT, java.util.Map.of("system", "DIRECTFILE", "type", "API"))
                .getResult();
        assertThat(subject.decrypt(legacy, EncryptionPurpose.TAX_RETURN_FACTS)).isEqualTo(PLAINTEXT);
    }

    @Test
    void rejectsLegacyUntaggedCiphertext_inEnforceMode() {
        DataEncryptDecrypt subject = subject("enforce");
        byte[] legacy = awsCrypto
                .encryptData(cmm, PLAINTEXT, java.util.Map.of("system", "DIRECTFILE", "type", "API"))
                .getResult();
        assertThatThrownBy(() -> subject.decrypt(legacy, EncryptionPurpose.TAX_RETURN_FACTS))
                .isInstanceOf(EncryptionContextMismatchException.class);
    }

    @Test
    void rejectsWrongPurpose_inEnforceMode_too() {
        DataEncryptDecrypt subject = subject("enforce");
        byte[] ciphertext = subject.encrypt(PLAINTEXT, EncryptionPurpose.TAX_RETURN_STORE, null);
        assertThatThrownBy(() -> subject.decrypt(ciphertext, EncryptionPurpose.TAX_RETURN_FACTS))
                .isInstanceOf(EncryptionContextMismatchException.class);
    }

    @Test
    void legacyTolerantDecryptAcceptsUntaggedEvenInEnforceMode() {
        // The data-import read paths, whose writers are outside this repository.
        DataEncryptDecrypt subject = subject("enforce");
        byte[] legacy =
                awsCrypto.encryptData(cmm, PLAINTEXT, java.util.Map.of()).getResult();
        assertThat(subject.decryptLegacyTolerant(legacy, EncryptionPurpose.DATA_IMPORT_POPULATED_DATA))
                .isEqualTo(PLAINTEXT);
    }

    @Test
    void warnModeReportsUntaggedCiphertext_soThePhaseCGateHasASignal() {
        DataEncryptDecrypt subject = subject("warn");
        byte[] legacy =
                awsCrypto.encryptData(cmm, PLAINTEXT, java.util.Map.of()).getResult();

        subject.decrypt(legacy, EncryptionPurpose.TAX_RETURN_FACTS);

        assertThat(subject.legacyCountFor(EncryptionPurpose.TAX_RETURN_FACTS)).isEqualTo(1L);
    }

    @Test
    void legacyTolerantDecryptDoesNotReport_soThePhaseCGateCanReachZero() {
        // The data-import populations are untagged permanently and by design. If reading them
        // emitted ENCRYPTION_CONTEXT_LEGACY, a log query for that marker could never return zero
        // and the Phase C gate would be unreachable.
        DataEncryptDecrypt subject = subject("warn");
        byte[] legacy =
                awsCrypto.encryptData(cmm, PLAINTEXT, java.util.Map.of()).getResult();

        subject.decryptLegacyTolerant(legacy, EncryptionPurpose.DATA_IMPORT_POPULATED_DATA);

        assertThat(subject.legacyCountFor(EncryptionPurpose.DATA_IMPORT_POPULATED_DATA))
                .isZero();
    }

    @Test
    void legacyTolerantDecryptStillRejectsAWrongPurpose() {
        // Permanent legacy tolerance is not permission to accept a mislabelled blob.
        DataEncryptDecrypt subject = subject("enforce");
        byte[] ciphertext = subject.encrypt(PLAINTEXT, EncryptionPurpose.TAX_RETURN_FACTS, null);
        assertThatThrownBy(
                        () -> subject.decryptLegacyTolerant(ciphertext, EncryptionPurpose.DATA_IMPORT_POPULATED_DATA))
                .isInstanceOf(EncryptionContextMismatchException.class);
    }

    @Test
    void encryptBindsTheActorIdWithoutMakingItVerified() {
        DataEncryptDecrypt subject = subject("enforce");
        byte[] ciphertext = subject.encrypt(PLAINTEXT, EncryptionPurpose.TAX_RETURN_FACTS, "actor-1");
        // A different reader, with no actor of its own, still reads it.
        assertThat(subject.decrypt(ciphertext, EncryptionPurpose.TAX_RETURN_FACTS))
                .isEqualTo(PLAINTEXT);
    }

    @Test
    void mismatchMessageNamesPurposesAndNothingElse() {
        DataEncryptDecrypt subject = subject("warn");
        byte[] ciphertext = subject.encrypt(PLAINTEXT, EncryptionPurpose.TAX_RETURN_STORE, "actor-1");
        assertThatThrownBy(() -> subject.decrypt(ciphertext, EncryptionPurpose.TAX_RETURN_FACTS))
                .hasMessageContaining("tax-return-facts")
                .hasMessageContaining("tax-return-store")
                .hasMessageNotContaining("actor-1");
    }

    @Test
    void refusalLogsTheMismatchMarker() {
        DataEncryptDecrypt subject = subject("warn");
        ch.qos.logback.classic.Logger logger =
                (ch.qos.logback.classic.Logger) org.slf4j.LoggerFactory.getLogger(DataEncryptDecrypt.class);
        ch.qos.logback.core.read.ListAppender<ch.qos.logback.classic.spi.ILoggingEvent> appender =
                new ch.qos.logback.core.read.ListAppender<>();
        appender.setContext((ch.qos.logback.classic.LoggerContext) org.slf4j.LoggerFactory.getILoggerFactory());
        appender.start();
        logger.addAppender(appender);
        try {
            byte[] ciphertext = subject.encrypt(PLAINTEXT, EncryptionPurpose.TAX_RETURN_STORE, null);
            assertThatThrownBy(() -> subject.decrypt(ciphertext, EncryptionPurpose.TAX_RETURN_FACTS))
                    .isInstanceOf(EncryptionContextMismatchException.class);

            assertThat(appender.list)
                    .anyMatch(event -> event.getLevel() == ch.qos.logback.classic.Level.ERROR
                            && event.getFormattedMessage().contains(EncryptionContextMismatchException.MARKER)
                            && event.getFormattedMessage().contains("tax-return-facts")
                            && event.getFormattedMessage().contains("tax-return-store"));
        } finally {
            logger.detachAppender(appender);
        }
    }
}
