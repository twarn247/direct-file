import { readFileSync } from 'fs';
import { resolve } from 'path';

import { CURRENT_TAX_YEAR } from '../constants/taxConstants.js';

// xml-src is a symlink to backend/src/main/resources/tax -- the same path readRawFacts.ts
// uses to build the fact dictionary.
const CONSTANTS_XML = resolve(__dirname, `../fact-dictionary/generate-src/xml-src/constants.xml`);

describe(`tax year constants`, () => {
  it(`CURRENT_TAX_YEAR agrees with the fact dictionary's /taxYear`, () => {
    // The tax year lives in three independent literals that must be incremented together.
    // Nothing else enforces that, and a mismatch does not fail loudly -- it surfaces later as
    // wrong amounts in facts derived from age or from year-relative thresholds. That is how
    // the HSA MFJ failures happened: fixtures measured against one year, facts against another.
    const xml = readFileSync(CONSTANTS_XML, `utf8`);

    // constants.xml has many <TaxYear> tags, one per fact that declares one. Scope to the
    // /taxYear fact's own block rather than matching the first tag in the file.
    const factBlock = /<Fact path="\/taxYear">([\s\S]*?)<\/Fact>/.exec(xml);
    expect(factBlock).not.toBeNull();

    const declaredTaxYear = /<TaxYear>(\d{4})<\/TaxYear>/.exec(factBlock![1]);
    const derivedValue = /<Int>(\d{4})<\/Int>/.exec(factBlock![1]);
    expect(declaredTaxYear).not.toBeNull();
    expect(derivedValue).not.toBeNull();

    expect(declaredTaxYear![1]).toBe(CURRENT_TAX_YEAR);
    expect(derivedValue![1]).toBe(CURRENT_TAX_YEAR);
  });
});
