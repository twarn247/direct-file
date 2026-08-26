package gov.irs.directfile.stateapi.authorization;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.*;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jwt.JWTClaimsSet;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import gov.irs.directfile.models.encryption.DataEncryptDecrypt;
import gov.irs.directfile.models.encryption.EncryptionPurpose;

@Slf4j
@Service
public class AuthorizationTokenService {
    private final DataEncryptDecrypt dataEncryptDecrypt;
    public static final String EXPORT_CLAIM_KEY = "tax-return-export-metadata";
    private final ObjectMapper mapper = new ObjectMapper();
    private final int authorizationCodeExpiresInterval;
    private final String signingKey;

    /**
     * HS256 keys that have been published in this repository's git history at some
     * point (application-development.yaml, then docker-compose.yaml's local-dev
     * default). Any deployment using one of these must rotate before serving traffic.
     */
    private static final Set<String> KNOWN_COMMITTED_KEYS =
            Set.of("GTc+SlI7C7ECPHAhAvIWqn2yAvzAGMVj", "1636cee96199ae396c208e65c86a1b21");

    private static final int MIN_SIGNING_KEY_BYTES = 32; // HS256 requires >= 256 bits

    public AuthorizationTokenService(
            DataEncryptDecrypt dataEncryptDecrypt,
            @Value("${authorization-token.signing-key}") String signingKey,
            @Value("${authorization-code.expires-interval-seconds: 600}") int authorizationCodeExpiresInterval) {
        if (signingKey == null || signingKey.isBlank()) {
            throw new IllegalStateException(
                    "authorization-token.signing-key is not set. Set STATE_API_AUTHORIZATION_TOKEN_SIGNING_KEY.");
        }
        if (signingKey.getBytes(StandardCharsets.UTF_8).length < MIN_SIGNING_KEY_BYTES) {
            throw new IllegalStateException(
                    "authorization-token.signing-key must be at least " + MIN_SIGNING_KEY_BYTES + " bytes for HS256.");
        }
        if (KNOWN_COMMITTED_KEYS.contains(signingKey)) {
            throw new IllegalStateException(
                    "authorization-token.signing-key is a key published in this repository's git history. Rotate it.");
        }

        this.dataEncryptDecrypt = dataEncryptDecrypt;
        this.signingKey = signingKey;
        this.authorizationCodeExpiresInterval = authorizationCodeExpiresInterval;
    }

    /**
     *  Creates a JWT (json web token) containing tax return export metadata which is first signed and then encrypted.
     */
    public Mono<String> generateAndEncrypt(AuthorizationTokenClaims claims) {
        return Mono.fromCallable(() -> {
            JWSSigner signer = new MACSigner(signingKey);
            Instant issuedAt = Instant.now();
            JWTClaimsSet jwtClaimsSet = new JWTClaimsSet.Builder()
                    .claim(EXPORT_CLAIM_KEY, claims)
                    .issueTime(Date.from(issuedAt))
                    .expirationTime(Date.from(issuedAt.plusSeconds(authorizationCodeExpiresInterval)))
                    .build();
            // create and sign a JWS (json web signature) containing the
            // claims as the payload
            JWSObject jwsObject = new JWSObject(
                    new JWSHeader.Builder(JWSAlgorithm.HS256).build(), new Payload(jwtClaimsSet.toJSONObject()));
            jwsObject.sign(signer);
            // encrypt the token with kms encryption sdk
            return encryptToken(signedJWSToBytes(jwsObject.serialize()));
        });
    }

    private byte[] signedJWSToBytes(String serializedJws) throws JsonProcessingException {
        // break the serialized JWSObject into its period-separated parts
        // before converting to byte array. We must do this prior to encryption to preserve
        // the separate parts of the token (header, signature, and payload)
        String[] serializedJWSParts = serializedJws.split("\\.");
        SignedJWSParts jwsParts =
                new SignedJWSParts(serializedJWSParts[0], serializedJWSParts[1], serializedJWSParts[2]);

        return mapper.writeValueAsBytes(jwsParts);
    }

    private String encryptToken(byte[] claims) {
        byte[] ciphertext = dataEncryptDecrypt.encrypt(claims, EncryptionPurpose.STATE_EXPORT_TOKEN, null);
        return Base64.getUrlEncoder().encodeToString(ciphertext);
    }
}
