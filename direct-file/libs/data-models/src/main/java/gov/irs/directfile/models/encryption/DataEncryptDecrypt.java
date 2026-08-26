package gov.irs.directfile.models.encryption;

import java.util.Arrays;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

import com.amazonaws.encryptionsdk.AwsCrypto;
import com.amazonaws.encryptionsdk.CryptoMaterialsManager;
import com.amazonaws.encryptionsdk.CryptoResult;
import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import jakarta.annotation.PostConstruct;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import gov.irs.directfile.models.autoconfigure.EncryptionContextProperties;

@Component
@Slf4j
@SuppressFBWarnings(value = "DM_DEFAULT_ENCODING", justification = "Initial Spotbugs Setup")
@SuppressWarnings("PMD.UnusedPrivateMethod")
public class DataEncryptDecrypt {
    /** Stable log marker. The Phase C gate is a log query for this string returning zero. */
    private static final String LEGACY_MARKER = "ENCRYPTION_CONTEXT_LEGACY";

    private static final long LEGACY_LOG_EVERY = 1000L;

    private final AwsCrypto awsCrypto;
    private final CryptoMaterialsManager cryptoMaterialsManager;
    private final EncryptionContextProperties encryptionContextProperties;
    private final ConcurrentHashMap<EncryptionPurpose, AtomicLong> legacyCounts = new ConcurrentHashMap<>();

    public DataEncryptDecrypt(
            AwsCrypto awsCrypto,
            CryptoMaterialsManager cryptoMaterialsManager,
            EncryptionContextProperties encryptionContextProperties) {
        this.awsCrypto = awsCrypto;
        this.cryptoMaterialsManager = cryptoMaterialsManager;
        this.encryptionContextProperties = encryptionContextProperties;
    }

    public byte[] encrypt(byte[] bytes, EncryptionPurpose purpose, String actorId) {
        CryptoResult<byte[], ?> encryptResult =
                awsCrypto.encryptData(cryptoMaterialsManager, bytes, EncryptionContexts.forPurpose(purpose, actorId));
        return encryptResult.getResult();
    }

    /**
     * Decrypts and verifies that the bound purpose is {@code expected}. Ciphertext written
     * before purposes existed is accepted or rejected according to
     * {@code direct-file.encryption.context-verification}.
     */
    public byte[] decrypt(byte[] ciphertext, EncryptionPurpose expected) {
        return decryptAndVerify(
                ciphertext,
                expected,
                encryptionContextProperties.isEnforcing() ? UntaggedPolicy.REJECT : UntaggedPolicy.REPORT);
    }

    /**
     * As {@link #decrypt}, but always tolerates untagged ciphertext regardless of mode.
     *
     * <p>For the data-import populations only: their writers live outside this repository,
     * so this codebase cannot migrate them and the tolerance is permanent. It is a distinct
     * method rather than a config exemption so the exception is visible at the call site.
     * Remove it when those writers adopt the purpose schema.
     */
    public byte[] decryptLegacyTolerant(byte[] ciphertext, EncryptionPurpose expected) {
        return decryptAndVerify(ciphertext, expected, UntaggedPolicy.ACCEPT_SILENTLY);
    }

    /** What to do with ciphertext that carries no bound purpose. */
    private enum UntaggedPolicy {
        /** Enforcing mode: the migration is finished, so untagged is a fault. */
        REJECT,
        /** Warn mode: accept, and emit the marker the Phase C gate is measured against. */
        REPORT,
        /**
         * Accept without reporting. Only for the permanently-pinned data-import paths: their
         * untagged state is expected and will never change, so reporting it would mean the
         * Phase C gate's log query could never reach zero.
         */
        ACCEPT_SILENTLY
    }

    private byte[] decryptAndVerify(byte[] ciphertext, EncryptionPurpose expected, UntaggedPolicy untaggedPolicy) {
        CryptoResult<byte[], ?> decryptResult = awsCrypto.decryptData(cryptoMaterialsManager, ciphertext);
        Map<String, String> context = decryptResult.getEncryptionContext();
        String found = context == null ? null : context.get(EncryptionContexts.PURPOSE_KEY);
        byte[] plaintext = decryptResult.getResult();

        if (found == null) {
            if (untaggedPolicy == UntaggedPolicy.REJECT) {
                return refuse(
                        plaintext,
                        "ciphertext carries no encryption context purpose; expected " + expected.wireValue());
            }
            if (untaggedPolicy == UntaggedPolicy.REPORT) {
                reportLegacy(expected);
            }
            return plaintext;
        }

        if (!found.equals(expected.wireValue())) {
            return refuse(
                    plaintext,
                    "encryption context purpose mismatch: expected " + expected.wireValue() + ", found " + found);
        }

        return plaintext;
    }

    private byte[] refuse(byte[] plaintext, String message) {
        Arrays.fill(plaintext, (byte) 0);
        throw new EncryptionContextMismatchException(message);
    }

    /**
     * Untagged decrypts seen by this instance for {@code purpose}. Package-private: it exists so
     * tests can assert that the permanently-pinned paths do not inflate the Phase C gate's signal.
     */
    long legacyCountFor(EncryptionPurpose purpose) {
        AtomicLong count = legacyCounts.get(purpose);
        return count == null ? 0L : count.get();
    }

    private void reportLegacy(EncryptionPurpose expected) {
        long count =
                legacyCounts.computeIfAbsent(expected, key -> new AtomicLong()).incrementAndGet();
        if (count == 1L || count % LEGACY_LOG_EVERY == 0L) {
            log.warn(
                    "{}: decrypted ciphertext with no bound purpose, expected={}, countThisInstance={}",
                    LEGACY_MARKER,
                    expected.wireValue(),
                    count);
        }
    }

    @PostConstruct
    private void checkKmsConnection() {
        byte[] testBytes = "something".getBytes();
        try {
            awsCrypto.encryptData(cryptoMaterialsManager, testBytes);
            log.info("encryption setup health check passed");
        } catch (Exception e) {
            log.error("test encrypt operation failed, check configuration");
            throw e;
        }
    }
}
