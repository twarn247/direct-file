package gov.irs.directfile.api.taxreturn.models;

import java.util.Map;
import java.util.UUID;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import gov.irs.directfile.api.authentication.NullAuthenticationException;
import gov.irs.directfile.api.config.identity.IdentityAttributes;
import gov.irs.directfile.api.config.identity.IdentitySupplier;
import gov.irs.directfile.models.FactTypeWithItem;
import gov.irs.directfile.models.encryption.DataEncryptDecrypt;
import gov.irs.directfile.models.encryption.EncryptionPurpose;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

public class TaxReturnEntityListenerTest {
    private DataEncryptDecrypt ded;
    private IdentitySupplier identitySupplier;
    private TaxReturnEntityListener listener;

    // TaxReturnEntityListener.configure writes the class's *static* fields, and Surefire runs this
    // module in a single reused JVM. Installing mocks there would leave them installed for every
    // later test that reuses an already-cached Spring context. Save and restore around each test.
    private static Object savedIdentitySupplier;
    private static Object savedFactsEncryptor;
    private static Object savedGenericStringEncryptor;

    private static Object readStatic(String name) throws Exception {
        java.lang.reflect.Field field = TaxReturnEntityListener.class.getDeclaredField(name);
        field.setAccessible(true);
        return field.get(null);
    }

    private static void writeStatic(String name, Object value) throws Exception {
        java.lang.reflect.Field field = TaxReturnEntityListener.class.getDeclaredField(name);
        field.setAccessible(true);
        field.set(null, value);
    }

    @BeforeEach
    void setUp() throws Exception {
        savedIdentitySupplier = readStatic("identitySupplier");
        savedFactsEncryptor = readStatic("factsEncryptor");
        savedGenericStringEncryptor = readStatic("genericStringEncryptor");

        ded = mock(DataEncryptDecrypt.class);
        identitySupplier = mock(IdentitySupplier.class);
        when(ded.encrypt(any(), any(EncryptionPurpose.class), any())).thenReturn(new byte[] {1, 2, 3});
        listener = new TaxReturnEntityListener();
        listener.configure(identitySupplier, ded, new ObjectMapper());
    }

    @AfterEach
    void restoreStatics() throws Exception {
        writeStatic("identitySupplier", savedIdentitySupplier);
        writeStatic("factsEncryptor", savedFactsEncryptor);
        writeStatic("genericStringEncryptor", savedGenericStringEncryptor);
    }

    private TaxReturn taxReturnWithContent() {
        TaxReturn taxReturn = new TaxReturn();
        taxReturn.setFacts(Map.<String, FactTypeWithItem>of());
        taxReturn.setStore("{}");
        return taxReturn;
    }

    @Test
    void encryptColumns_writesFactsAndStoreUnderDistinctPurposes() {
        when(identitySupplier.get()).thenThrow(new NullAuthenticationException());
        TaxReturn taxReturn = new TaxReturn();
        taxReturn.setFacts(Map.of(
                "/foo",
                new FactTypeWithItem(
                        "gov.irs.factgraph.persisters.StringWrapper",
                        com.fasterxml.jackson.databind.node.TextNode.valueOf("baz"))));
        taxReturn.setStore("{}");

        listener.encryptColumns(taxReturn);

        ArgumentCaptor<EncryptionPurpose> purposes = ArgumentCaptor.captor();
        verify(ded, org.mockito.Mockito.atLeast(2)).encrypt(any(), purposes.capture(), any());
        assertThat(purposes.getAllValues())
                .contains(EncryptionPurpose.TAX_RETURN_FACTS, EncryptionPurpose.TAX_RETURN_STORE);
    }

    @Test
    void encryptColumns_bindsTheActorIdWhenAPrincipalIsInScope() {
        UUID externalId = UUID.randomUUID();
        // IdentityAttributes is a record, so it is final and cannot be mocked - build a real one.
        IdentityAttributes attributes =
                new IdentityAttributes(UUID.randomUUID(), externalId, "taxpayer@example.com", "123456789");
        when(identitySupplier.get()).thenReturn(attributes);

        listener.encryptColumns(taxReturnWithContent());

        ArgumentCaptor<String> actorId = ArgumentCaptor.captor();
        verify(ded, org.mockito.Mockito.atLeastOnce()).encrypt(any(), any(EncryptionPurpose.class), actorId.capture());
        assertThat(actorId.getValue()).isEqualTo(externalId.toString());
    }

    @Test
    void encryptColumns_omitsTheActorIdForSystemTriggeredWrites() {
        when(identitySupplier.get()).thenThrow(new NullAuthenticationException());

        listener.encryptColumns(taxReturnWithContent());

        ArgumentCaptor<String> actorId = ArgumentCaptor.captor();
        verify(ded, org.mockito.Mockito.atLeastOnce()).encrypt(any(), any(EncryptionPurpose.class), actorId.capture());
        assertThat(actorId.getValue()).isNull();
    }

    @Test
    void decryptColumns_readsEachColumnUnderItsOwnPurpose() {
        when(ded.decrypt(any(), any(EncryptionPurpose.class))).thenReturn("{}".getBytes());
        TaxReturn taxReturn = new TaxReturn();
        taxReturn.setFactsCipherText(java.util.Base64.getEncoder().encodeToString(new byte[] {1, 2, 3}));
        taxReturn.setStoreCipherText(java.util.Base64.getEncoder().encodeToString(new byte[] {1, 2, 3}));

        listener.decryptColumns(taxReturn);

        ArgumentCaptor<EncryptionPurpose> purposes = ArgumentCaptor.captor();
        verify(ded, org.mockito.Mockito.atLeast(2)).decrypt(any(), purposes.capture());
        assertThat(purposes.getAllValues())
                .contains(EncryptionPurpose.TAX_RETURN_FACTS, EncryptionPurpose.TAX_RETURN_STORE);
    }
}
