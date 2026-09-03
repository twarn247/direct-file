package gov.irs.directfile.models.encryption;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

import com.amazonaws.encryptionsdk.AwsCrypto;
import com.amazonaws.encryptionsdk.CryptoMaterialsManager;
import com.amazonaws.encryptionsdk.CryptoResult;
import jakarta.annotation.PostConstruct;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import gov.irs.directfile.models.autoconfigure.EncryptionContextProperties;

@Component
@Slf4j
@SuppressWarnings("PMD.UnusedPrivateMethod")
public class DataEncryptDecrypt {
    /**
     * Stable log marker for ciphertext seen with no bound purpose. Useful for watching a
     * sweep in progress, but the Phase C gate itself is
     * {@code EncryptionBackfillProgressRepository.allTablesCleanlyMigrated()} — a query
     * against the persisted counters, not a search over logs whose retention this class has
     * no control over.
     */
    private static final String LEGACY_MARKER = "ENCRYPTION_CONTEXT_LEGACY";

    /** As {@link #LEGACY_MARKER}, but for ciphertext seen with no bound record. */
    private static final String RECORD_LEGACY_MARKER = "ENCRYPTION_CONTEXT_RECORD_LEGACY";

    private static final long LEGACY_LOG_EVERY = 1000L;

    private final AwsCrypto awsCrypto;
    private final CryptoMaterialsManager cryptoMaterialsManager;
    private final EncryptionContextProperties encryptionContextProperties;
    private final ConcurrentHashMap<EncryptionPurpose, AtomicLong> legacyCounts = new ConcurrentHashMap<>();
    private final AtomicLong legacyRecordCount = new AtomicLong();

    public DataEncryptDecrypt(
            AwsCrypto awsCrypto,
            CryptoMaterialsManager cryptoMaterialsManager,
            EncryptionContextProperties encryptionContextProperties) {
        this.awsCrypto = awsCrypto;
        this.cryptoMaterialsManager = cryptoMaterialsManager;
        this.encryptionContextProperties = encryptionContextProperties;
    }

    public byte[] encrypt(byte[] bytes, EncryptionPurpose purpose, String actorId) {
        return encrypt(bytes, purpose, actorId, null);
    }

    /** As {@link #encrypt(byte[], EncryptionPurpose, String)}, additionally binding a record id. */
    public byte[] encrypt(byte[] bytes, EncryptionPurpose purpose, String actorId, String recordId) {
        CryptoResult<byte[], ?> encryptResult = awsCrypto.encryptData(
                cryptoMaterialsManager, bytes, EncryptionContexts.forPurpose(purpose, actorId, recordId));
        return encryptResult.getResult();
    }

    /**
     * Decrypts and verifies that the bound purpose is {@code expected}. Ciphertext written
     * before purposes existed is accepted or rejected according to
     * {@code direct-file.encryption.context-verification}.
     */
    public byte[] decrypt(byte[] ciphertext, EncryptionPurpose expected) {
        return decrypt(ciphertext, expected, null);
    }

    /**
     * As {@link #decrypt(byte[], EncryptionPurpose)}, additionally verifying the bound
     * {@code record} equals {@code expectedRecordId} when non-null. A ciphertext with no
     * bound record is accepted or rejected according to
     * {@code direct-file.encryption.record-context-verification}; a ciphertext bound to a
     * <em>different</em> record is always refused, in either mode.
     */
    public byte[] decrypt(byte[] ciphertext, EncryptionPurpose expected, String expectedRecordId) {
        return decryptAndVerify(
                ciphertext,
                expected,
                expectedRecordId,
                encryptionContextProperties.isEnforcing() ? UntaggedPolicy.REJECT : UntaggedPolicy.REPORT);
    }

    /**
     * As {@link #decrypt(byte[], EncryptionPurpose)}, but always tolerates untagged ciphertext
     * regardless of mode.
     *
     * <p>For the data-import populations only: their writers live outside this repository,
     * so this codebase cannot migrate them and the tolerance is permanent. It is a distinct
     * method rather than a config exemption so the exception is visible at the call site.
     * Remove it when those writers adopt the purpose schema.
     */
    public byte[] decryptLegacyTolerant(byte[] ciphertext, EncryptionPurpose expected) {
        return decryptAndVerify(ciphertext, expected, null, UntaggedPolicy.ACCEPT_SILENTLY);
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

    private byte[] decryptAndVerify(
            byte[] ciphertext, EncryptionPurpose expected, String expectedRecordId, UntaggedPolicy untaggedPolicy) {
        CryptoResult<byte[], ?> decryptResult = awsCrypto.decryptData(cryptoMaterialsManager, ciphertext);
        Map<String, String> context = decryptResult.getEncryptionContext();
        String foundPurpose = context == null ? null : context.get(EncryptionContexts.PURPOSE_KEY);
        byte[] plaintext = decryptResult.getResult();

        if (foundPurpose == null) {
            if (untaggedPolicy == UntaggedPolicy.REJECT) {
                return refuse(plaintext, expected, null);
            }
            if (untaggedPolicy == UntaggedPolicy.REPORT) {
                reportLegacy(expected);
            }
            return plaintext;
        }

        if (!foundPurpose.equals(expected.wireValue())) {
            return refuse(plaintext, expected, foundPurpose);
        }

        if (expectedRecordId != null) {
            String foundRecord = context.get(EncryptionContexts.RECORD_KEY);
            if (foundRecord == null) {
                if (encryptionContextProperties.isRecordEnforcing()) {
                    return refuseRecordMismatch(plaintext, expectedRecordId, null);
                }
                reportLegacyRecord();
            } else if (!foundRecord.equals(expectedRecordId)) {
                return refuseRecordMismatch(plaintext, expectedRecordId, foundRecord);
            }
        }

        return plaintext;
    }

    /**
     * Refuses a decrypted plaintext whose bound purpose did not match. Zeroes the plaintext, logs
     * the stable {@link EncryptionContextMismatchException#MARKER} once here — the single place
     * every refusal passes through, so the marker fires for every purpose this codebase verifies,
     * not just the callers that happen to add their own catch — and throws.
     *
     * <p>{@code found} is null for "no purpose bound at all" (rejected only under enforce mode)
     * and a string for "bound to some other purpose" (rejected in every mode). Sanitized through
     * {@link EncryptionPurpose#fromWireValue} before it ever reaches a log line or an exception
     * message: it was read out of the ciphertext's context, which this class does not otherwise
     * treat as trusted input.
     */
    private byte[] refuse(byte[] plaintext, EncryptionPurpose expected, String found) {
        String safeFound = found == null
                ? "<none>"
                : EncryptionPurpose.fromWireValue(found)
                        .map(EncryptionPurpose::wireValue)
                        .orElse("<unrecognized>");
        String message =
                "encryption context purpose mismatch: expected " + expected.wireValue() + ", found " + safeFound;
        log.error("{}: {}", EncryptionContextMismatchException.MARKER, message);
        Arrays.fill(plaintext, (byte) 0);
        throw new EncryptionContextMismatchException(message);
    }

    /**
     * As {@link #refuse}, but for a record mismatch rather than a purpose mismatch. A distinct
     * method rather than a shared one with a field-name parameter: the two failure modes have
     * different messages and no shared sanitization logic (a record id is a UUID string, not a
     * value from a closed enum), and keeping them apart matches how {@link
     * #decryptLegacyTolerant} is a distinct method rather than a config branch on the same one.
     */
    private byte[] refuseRecordMismatch(byte[] plaintext, String expectedRecordId, String foundRecordId) {
        String message = "encryption context record mismatch: expected record=" + expectedRecordId + ", found record="
                + (foundRecordId == null ? "<none>" : foundRecordId);
        log.error("{}: {}", EncryptionContextMismatchException.MARKER, message);
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

    /** As {@link #legacyCountFor}, but for the record key. Not split by purpose: unlike purpose
     * mismatches, which are meaningful per data type, "how many rows have no bound record yet"
     * is one number regardless of which column it came from. */
    long legacyRecordCount() {
        return legacyRecordCount.get();
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

    private void reportLegacyRecord() {
        long count = legacyRecordCount.incrementAndGet();
        if (count == 1L || count % LEGACY_LOG_EVERY == 0L) {
            log.warn(
                    "{}: decrypted ciphertext with no bound record, countThisInstance={}", RECORD_LEGACY_MARKER, count);
        }
    }

    @PostConstruct
    private void checkKmsConnection() {
        byte[] testBytes = "something".getBytes(StandardCharsets.UTF_8);
        try {
            awsCrypto.encryptData(cryptoMaterialsManager, testBytes);
            log.info("encryption setup health check passed");
        } catch (Exception e) {
            log.error("test encrypt operation failed, check configuration");
            throw e;
        }
    }
}
