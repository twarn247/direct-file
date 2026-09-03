package gov.irs.directfile.api.user;

import java.util.Optional;
import java.util.UUID;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import gov.irs.directfile.api.audit.AuditLogElement;
import gov.irs.directfile.api.audit.AuditService;
import gov.irs.directfile.api.config.identity.IdentityAttributes;
import gov.irs.directfile.api.config.identity.IdentitySupplier;
import gov.irs.directfile.api.user.domain.UserInfo;
import gov.irs.directfile.api.user.models.User;
import gov.irs.directfile.audit.events.TinType;

@Service
public class UserService {
    private final UserRepository userRepo;
    private final IdentitySupplier identitySupplier;
    private final AuditService auditService;

    public UserService(
            final UserRepository userRepo, final IdentitySupplier identitySupplier, final AuditService auditService) {
        this.userRepo = userRepo;
        this.identitySupplier = identitySupplier;
        this.auditService = auditService;
    }

    public UserInfo getCurrentUserInfo() {
        IdentityAttributes attributes = identitySupplier.get();
        auditService.addEventProperty(AuditLogElement.USER_TIN_LAST4, lastFour(attributes.tin()));
        auditService.addEventProperty(AuditLogElement.USER_TIN_TYPE, TinType.INDIVIDUAL.toString());
        return new UserInfo(attributes.id(), attributes.externalId(), attributes.email(), attributes.tin());
    }

    /**
     * The last four digits of a TIN, for audit correlation.
     *
     * <p>The full TIN must not enter the audit event map: AuditService serializes every
     * property in that map as a fluent key-value pair, so whether it reaches log output
     * depends entirely on each encoder's allowlist. Four digits support the correlation an
     * investigator actually performs without putting the identifier itself one
     * configuration mistake away from being logged.
     *
     * <p>Returns null for a null TIN — AuditService.addEventProperty already ignores null
     * values — and returns the input unchanged if it is shorter than four characters,
     * rather than throwing.
     */
    private static String lastFour(String tin) {
        if (tin == null) {
            return null;
        }
        if (tin.length() < 4) {
            // Malformed: a real TIN is never this short. Emitting it unchanged would put
            // more into the audit map than "last four" promises, for no operational benefit
            // -- a fixed placeholder is both safer and a clearer signal that validation
            // upstream of this method failed.
            return "????";
        }
        return tin.substring(tin.length() - 4);
    }

    @Transactional(readOnly = true)
    public Optional<User> getUser(UUID userId) {
        return userRepo.findById(userId);
    }

    @Transactional(readOnly = true)
    public Optional<User> getOrCreateUserDev() {
        UUID externalId = UUID.fromString("00000000-0000-0000-0000-000000000000");
        Optional<User> optUser;
        optUser = userRepo.findById(UUID.fromString("11111111-1111-1111-1111-111111111111"));
        if (optUser.isEmpty()) {
            optUser = userRepo.findByExternalId(externalId);
        }
        if (optUser.isEmpty()) {
            User u = new User(externalId);
            u.setAccessGranted(true);
            return Optional.of(userRepo.save(u));
        }
        return optUser;
    }
}
