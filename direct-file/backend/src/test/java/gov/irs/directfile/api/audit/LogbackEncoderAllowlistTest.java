package gov.irs.directfile.api.audit;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.stream.Stream;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Guards the M-1 fix: the audit event map is serialized by LogstashEncoder as fluent
 * key-value pairs, and an encoder with no includeKeyValueKeyName entries emits every one
 * of them. The same applies to MDC entries and includeMdcKeyName.
 *
 * <p>Any new logback configuration that uses LogstashEncoder must declare an allowlist,
 * or taxpayer identifiers reach log output the moment someone adds one to the audit map.
 */
class LogbackEncoderAllowlistTest {

    private static final Path RESOURCES = Path.of("src/main/resources");

    static Stream<Path> logbackConfigurations() throws IOException {
        try (Stream<Path> files = Files.list(RESOURCES)) {
            return files
                    .filter(p -> p.getFileName().toString().startsWith("logback"))
                    .filter(p -> p.getFileName().toString().endsWith(".xml"))
                    .toList()
                    .stream();
        }
    }

    @ParameterizedTest
    @MethodSource("logbackConfigurations")
    void everyLogstashEncoderDeclaresAnAllowlist(Path config) throws IOException {
        String contents = Files.readString(config, StandardCharsets.UTF_8);

        if (!contents.contains("LogstashEncoder")) {
            // Pattern-based configurations do not render fluent key-value pairs at all.
            return;
        }

        assertThat(contents)
                .as(
                        "%s uses LogstashEncoder but declares no includeKeyValueKeyName, so it emits "
                                + "every audit event property including any taxpayer identifier",
                        config.getFileName())
                .contains("includeKeyValueKeyName");

        assertThat(contents)
                .as(
                        "%s uses LogstashEncoder but declares no includeMdcKeyName, so it emits every " + "MDC entry",
                        config.getFileName())
                .contains("includeMdcKeyName");
    }

    @ParameterizedTest
    @MethodSource("logbackConfigurations")
    void noConfigurationAllowlistsATaxpayerIdentifier(Path config) throws IOException {
        String contents = Files.readString(config, StandardCharsets.UTF_8);

        // If someone ever adds these to an allowlist, that is a deliberate act that should
        // fail here rather than pass silently.
        List<String> forbidden = List.of(
                "<includeKeyValueKeyName>userTin</includeKeyValueKeyName>",
                "<includeMdcKeyName>email</includeMdcKeyName>");

        assertThat(forbidden).allSatisfy(entry -> assertThat(contents)
                .as("%s allowlists a taxpayer identifier: %s", config.getFileName(), entry)
                .doesNotContain(entry));
    }
}
