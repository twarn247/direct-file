package gov.irs.directfile.models.encryption;

import java.util.Map;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

public class EncryptionContextsTest {

    @Test
    void forPurpose_setsPurposeAndSystem() {
        Map<String, String> context = EncryptionContexts.forPurpose(EncryptionPurpose.TAX_RETURN_FACTS);
        assertThat(context)
                .containsEntry("purpose", "tax-return-facts")
                .containsEntry("system", "DIRECT-FILE")
                .doesNotContainKey("id");
    }

    @Test
    void forPurpose_withActorId_addsIdWithoutDisturbingVerifiedKeys() {
        Map<String, String> context = EncryptionContexts.forPurpose(EncryptionPurpose.TAX_RETURN_STORE, "abc-123");
        assertThat(context)
                .containsEntry("purpose", "tax-return-store")
                .containsEntry("system", "DIRECT-FILE")
                .containsEntry("id", "abc-123");
    }

    @Test
    void forPurpose_withNullOrBlankActorId_omitsIdRatherThanWritingEmpty() {
        assertThat(EncryptionContexts.forPurpose(EncryptionPurpose.TAX_RETURN_STORE, null))
                .doesNotContainKey("id");
        assertThat(EncryptionContexts.forPurpose(EncryptionPurpose.TAX_RETURN_STORE, "   "))
                .doesNotContainKey("id");
    }

    @Test
    void forPurpose_returnsAnImmutableMap() {
        Map<String, String> context = EncryptionContexts.forPurpose(EncryptionPurpose.STATE_EXPORT_TOKEN);
        assertThatThrownBy(() -> context.put("purpose", "something-else"))
                .isInstanceOf(UnsupportedOperationException.class);
    }

    @Test
    void everyPurposeHasADistinctWireValue() {
        long distinct = java.util.Arrays.stream(EncryptionPurpose.values())
                .map(EncryptionPurpose::wireValue)
                .distinct()
                .count();
        assertThat(distinct).isEqualTo(EncryptionPurpose.values().length);
    }

    @Test
    void factsAndStoreAreDistinguishable() {
        // The whole point of the finding: these two were identical before this change.
        assertThat(EncryptionContexts.forPurpose(EncryptionPurpose.TAX_RETURN_FACTS))
                .isNotEqualTo(EncryptionContexts.forPurpose(EncryptionPurpose.TAX_RETURN_STORE));
    }

    @Test
    void fromWireValue_roundTripsAndRejectsUnknown() {
        assertThat(EncryptionPurpose.fromWireValue("tax-return-facts")).contains(EncryptionPurpose.TAX_RETURN_FACTS);
        assertThat(EncryptionPurpose.fromWireValue("not-a-purpose")).isEmpty();
        assertThat(EncryptionPurpose.fromWireValue(null)).isEmpty();
    }

    @Test
    void forPurpose_withRecordId_addsRecordWithoutDisturbingVerifiedKeys() {
        Map<String, String> context =
                EncryptionContexts.forPurpose(EncryptionPurpose.TAX_RETURN_FACTS, "actor-1", "row-42");
        assertThat(context)
                .containsEntry("purpose", "tax-return-facts")
                .containsEntry("id", "actor-1")
                .containsEntry("record", "row-42");
    }

    @Test
    void forPurpose_withNullOrBlankRecordId_omitsRecordRatherThanWritingEmpty() {
        assertThat(EncryptionContexts.forPurpose(EncryptionPurpose.TAX_RETURN_FACTS, "actor-1", null))
                .doesNotContainKey("record");
        assertThat(EncryptionContexts.forPurpose(EncryptionPurpose.TAX_RETURN_FACTS, "actor-1", "   "))
                .doesNotContainKey("record");
    }
}
