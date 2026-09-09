import fs from 'fs';
// fast-xml-parser is declared under devDependencies, not dependencies, even though this
// is a runtime XML-parsing library rather than build tooling -- that's correct only
// because this file is never reachable from browser-bundled code. Its own use of Node's
// `fs` module above is one signal of that; the fuller trace: this module's only
// importers are generate.ts (invoked solely via vite-node, in prebuild:ts and the
// pretest:* hooks) and this package's *.test.ts files. The two all-screens components
// that import a sibling module in generate-src/ (dependencyGraph.js) do not import this
// one. Confirmed empirically too: fast-xml-parser does not appear in dist/assets/*.js
// after `npm run build:development`. If this file (or fast-xml-parser) is ever imported
// from application code reachable at runtime, fast-xml-parser must move back to
// dependencies -- devDependencies is not scanned by the client's Trivy gate.
import { XMLParser, XMLValidator, X2jOptions } from 'fast-xml-parser';
import { RawFact } from '../FactTypes.js';

export default function readRawFacts(): RawFact[] {
  const FACT_DICTIONARY_FOLDER = `./src/fact-dictionary/generate-src/xml-src/`;

  const XML_PARSER_OPTIONS: X2jOptions = {
    ignoreAttributes: false,
    attributeNamePrefix: `@`,
    ignoreDeclaration: true,
    trimValues: true,
    parseAttributeValue: false,
  };

  // We assume all xml files in the tax folder are Fact Dictionary Fragments.
  const dictionaryFiles = fs.readdirSync(FACT_DICTIONARY_FOLDER).filter((f) => f.endsWith(`.xml`));

  const allRawFacts: RawFact[] = [];

  for (const dictionaryFile of dictionaryFiles) {
    // eslint-disable-next-line no-console
    console.log(`Reading file ${dictionaryFile}`);
    // nosemgrep: eslint.detect-non-literal-fs-filename
    const rawXmlString = fs.readFileSync(FACT_DICTIONARY_FOLDER + dictionaryFile, `utf-8`);

    const xmlValidationResult = XMLValidator.validate(rawXmlString, {
      allowBooleanAttributes: true,
    });

    // must use strict equality here, since this will return an object if untrue
    if (xmlValidationResult !== true) {
      // not client facing, so we'll allow console here
      // eslint-disable-next-line no-console
      console.error(`XML validation error`, xmlValidationResult);
      throw new Error(`XML validation error`);
    }

    const parser = new XMLParser(XML_PARSER_OPTIONS);
    const parsedDictionary = parser.parse(rawXmlString);

    if (!parsedDictionary.FactDictionaryModule) {
      throw new Error(`XML did not start with element "FactDictionaryModule`);
    }

    const rawFacts: RawFact[] = [].concat(parsedDictionary.FactDictionaryModule.Facts.Fact);
    rawFacts.forEach((fact: RawFact) => {
      fact.srcFile = dictionaryFile;
    });
    allRawFacts.push(...rawFacts);
  }
  return allRawFacts;
}
