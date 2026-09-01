package gov.irs.directfile.models.encryption;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;
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

public class GenericStringEncryptorTest {

    // A taxpayer name with a diacritic, a CJK name, and an astral-plane code point.
    // All three encode differently under UTF-8 than under any single-byte default charset.
    private static final String NON_ASCII = "José 李雷 👋";

    private GenericStringEncryptor subject;
    private DataEncryptDecrypt dataEncryptDecrypt;

    @BeforeEach
    void setUp() {
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
        properties.setContextVerification("warn");
        dataEncryptDecrypt = new DataEncryptDecrypt(AwsCrypto.standard(), cmm, properties);
        subject = new GenericStringEncryptor(dataEncryptDecrypt);
    }

    @Test
    void roundTripsNonAsciiUnchanged() {
        String stored = subject.convertToDatabaseColumn(NON_ASCII, EncryptionPurpose.TAX_RETURN_FACTS, null);

        assertThat(subject.convertToEntityAttribute(stored, EncryptionPurpose.TAX_RETURN_FACTS))
                .isEqualTo(NON_ASCII);
    }

    @Test
    void encryptsExactlyTheUtf8Bytes() {
        // The guarantee, not just the round trip: what goes into the ciphertext is UTF-8,
        // independent of the JVM's default charset.
        String stored = subject.convertToDatabaseColumn(NON_ASCII, EncryptionPurpose.TAX_RETURN_FACTS, null);
        byte[] plaintext =
                dataEncryptDecrypt.decrypt(Base64.getDecoder().decode(stored), EncryptionPurpose.TAX_RETURN_FACTS);

        assertThat(plaintext).isEqualTo(NON_ASCII.getBytes(StandardCharsets.UTF_8));
    }

    @Test
    void decryptsUtf8BytesWrittenDirectly() {
        byte[] ciphertext = dataEncryptDecrypt.encrypt(
                NON_ASCII.getBytes(StandardCharsets.UTF_8), EncryptionPurpose.TAX_RETURN_FACTS, null);
        String stored = Base64.getEncoder().encodeToString(ciphertext);

        assertThat(subject.convertToEntityAttribute(stored, EncryptionPurpose.TAX_RETURN_FACTS))
                .isEqualTo(NON_ASCII);
    }

    @Test
    void passesNullAndEmptyThrough() {
        assertThat(subject.convertToDatabaseColumn(null, EncryptionPurpose.TAX_RETURN_FACTS, null))
                .isNull();
        assertThat(subject.convertToDatabaseColumn("", EncryptionPurpose.TAX_RETURN_FACTS, null))
                .isEmpty();
        assertThat(subject.convertToEntityAttribute(null, EncryptionPurpose.TAX_RETURN_FACTS))
                .isNull();
        assertThat(subject.convertToEntityAttribute("", EncryptionPurpose.TAX_RETURN_FACTS))
                .isEmpty();
    }
}
