package gov.irs.directfile.models.autoconfigure;

import jakarta.annotation.PostConstruct;
import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;

@Getter
@Setter
@ConfigurationProperties("direct-file.encryption")
public class EncryptionContextProperties {
    public static final String WARN = "warn";
    public static final String ENFORCE = "enforce";

    /**
     * How to treat ciphertext written before encryption contexts carried a purpose:
     * "warn" accepts and reports it, "enforce" rejects it. A ciphertext carrying the
     * <em>wrong</em> purpose is rejected under both.
     */
    private String contextVerification = WARN;

    /**
     * As {@link #contextVerification}, but for the {@code record} key rather than
     * {@code purpose}, and independent of it: {@code purpose} enforcement could be turned on
     * before every row carries a bound {@code record}, and doing so must not also start
     * rejecting rows the record backfill has not reached yet. A ciphertext carrying the
     * <em>wrong</em> record is rejected under both modes, exactly as a wrong purpose is.
     */
    private String recordContextVerification = WARN;

    public boolean isEnforcing() {
        return ENFORCE.equalsIgnoreCase(contextVerification);
    }

    public boolean isRecordEnforcing() {
        return ENFORCE.equalsIgnoreCase(recordContextVerification);
    }

    @PostConstruct
    public void validate() {
        validateMode("context-verification", contextVerification);
        validateMode("record-context-verification", recordContextVerification);
    }

    private static void validateMode(String propertyName, String value) {
        if (!WARN.equalsIgnoreCase(value) && !ENFORCE.equalsIgnoreCase(value)) {
            throw new IllegalStateException("direct-file.encryption." + propertyName + " must be '" + WARN + "' or '"
                    + ENFORCE + "', got: " + value);
        }
    }
}
