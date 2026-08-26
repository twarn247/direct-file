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

    public boolean isEnforcing() {
        return ENFORCE.equalsIgnoreCase(contextVerification);
    }

    @PostConstruct
    void validate() {
        if (!WARN.equalsIgnoreCase(contextVerification) && !ENFORCE.equalsIgnoreCase(contextVerification)) {
            throw new IllegalStateException("direct-file.encryption.context-verification must be '" + WARN + "' or '"
                    + ENFORCE + "', got: " + contextVerification);
        }
    }
}
