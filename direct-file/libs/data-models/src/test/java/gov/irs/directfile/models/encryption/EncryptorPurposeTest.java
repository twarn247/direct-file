package gov.irs.directfile.models.encryption;

import java.util.Map;

import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

public class EncryptorPurposeTest {

    @Test
    void genericStringEncryptor_encryptsUnderTheGivenPurposeAndActor() {
        DataEncryptDecrypt ded = mock(DataEncryptDecrypt.class);
        when(ded.encrypt(any(), any(EncryptionPurpose.class), any())).thenReturn(new byte[] {1, 2, 3});

        new GenericStringEncryptor(ded).convertToDatabaseColumn("value", EncryptionPurpose.TAX_RETURN_STORE, "actor-1");

        verify(ded).encrypt(any(), eq(EncryptionPurpose.TAX_RETURN_STORE), eq("actor-1"));
    }

    @Test
    void genericStringEncryptor_decryptsUnderTheExpectedPurpose() {
        DataEncryptDecrypt ded = mock(DataEncryptDecrypt.class);
        when(ded.decrypt(any(), any(EncryptionPurpose.class))).thenReturn("value".getBytes());

        String result = new GenericStringEncryptor(ded)
                .convertToEntityAttribute(
                        java.util.Base64.getEncoder().encodeToString(new byte[] {1, 2, 3}),
                        EncryptionPurpose.TAX_RETURN_STORE);

        assertThat(result).isEqualTo("value");
        verify(ded).decrypt(any(), eq(EncryptionPurpose.TAX_RETURN_STORE));
    }

    @Test
    void genericStringEncryptor_legacyTolerantPathUsesTheLegacyTolerantDecrypt() {
        DataEncryptDecrypt ded = mock(DataEncryptDecrypt.class);
        when(ded.decryptLegacyTolerant(any(), any(EncryptionPurpose.class))).thenReturn("value".getBytes());

        new GenericStringEncryptor(ded)
                .convertToEntityAttributeLegacyTolerant(
                        java.util.Base64.getEncoder().encodeToString(new byte[] {1, 2, 3}),
                        EncryptionPurpose.DATA_IMPORT_POPULATED_DATA);

        verify(ded).decryptLegacyTolerant(any(), eq(EncryptionPurpose.DATA_IMPORT_POPULATED_DATA));
    }

    @Test
    void genericStringEncryptor_nullAndEmptyPassThroughWithoutTouchingCrypto() {
        DataEncryptDecrypt ded = mock(DataEncryptDecrypt.class);
        GenericStringEncryptor subject = new GenericStringEncryptor(ded);

        assertThat(subject.convertToDatabaseColumn(null, EncryptionPurpose.TAX_RETURN_STORE, null))
                .isNull();
        assertThat(subject.convertToDatabaseColumn("", EncryptionPurpose.TAX_RETURN_STORE, null))
                .isEmpty();
        assertThat(subject.convertToEntityAttribute(null, EncryptionPurpose.TAX_RETURN_STORE))
                .isNull();
        org.mockito.Mockito.verifyNoInteractions(ded);
    }

    @Test
    void factsEncryptor_encryptsUnderFactsPurpose() {
        DataEncryptDecrypt ded = mock(DataEncryptDecrypt.class);
        when(ded.encrypt(any(), any(EncryptionPurpose.class), any())).thenReturn(new byte[] {1, 2, 3});

        new FactsEncryptor(ded)
                .convertToDatabaseColumn(
                        Map.of(
                                "/foo",
                                new gov.irs.directfile.models.FactTypeWithItem(
                                        "gov.irs.factgraph.persisters.StringWrapper",
                                        com.fasterxml.jackson.databind.node.TextNode.valueOf("baz"))),
                        EncryptionPurpose.TAX_RETURN_FACTS,
                        null);

        ArgumentCaptor<EncryptionPurpose> purpose = ArgumentCaptor.captor();
        verify(ded).encrypt(any(), purpose.capture(), any());
        assertThat(purpose.getValue()).isEqualTo(EncryptionPurpose.TAX_RETURN_FACTS);
    }
}
