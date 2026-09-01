package gov.irs.directfile.api.taxreturn;

import org.junit.jupiter.api.Test;
import org.springframework.context.annotation.Profile;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

public class MockDataImportControllerProfileTest {

    @Test
    public void mockDataImportControllerIsGatedToTheMockProfile() {
        Profile profile = MockDataImportController.class.getAnnotation(Profile.class);
        assertNotNull(
                profile,
                "MockDataImportController reads x-data-import-profile and x-data-import-dob straight from"
                        + " request headers. It must declare @Profile(\"mock\") rather than relying on the"
                        + " constructor's ClassCastException to keep it out of other profiles.");
        assertArrayEquals(new String[] {"mock"}, profile.value());
    }

    @Test
    public void taxReturnControllerIsExcludedFromTheMockProfile() {
        // The two are complements. If this one loses !mock, both controllers load under the
        // mock profile and the duplicate @RequestMapping becomes an ambiguous mapping again.
        Profile profile = TaxReturnController.class.getAnnotation(Profile.class);
        assertNotNull(profile, "TaxReturnController must declare @Profile(\"!mock\").");
        assertArrayEquals(new String[] {"!mock"}, profile.value());
    }
}
