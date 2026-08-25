import { getTranslatedLink, parseHttpsUrl, urlHasLanguagePlaceholder } from './urlUtils.js';

const URL_WITH_PLACEHOLDER = `www.directfile.gov/{LANGUAGE_CODE}/home/`;
const URL_WITH_QUERY_PARAM_PLACEHOLDER = `www.directfile.gov/home?lang={LANGUAGE_CODE}`;
const URL_WITHOUT_PLACEHOLDER = `www.directfile.gov/home/`;
const URL_WITH_MISSPELLED_PLACEHOLDER = `www.directfile.gov/{LANG_CODE}/home/`;

const URL_EN = `www.directfile.gov/en/home/`;
const URL_ES = `www.directfile.gov/es/home/`;
const URL_ENGLISH = `www.directfile.gov/home?lang=english`;

describe(`urlUtils`, () => {
  describe(urlHasLanguagePlaceholder.name, () => {
    it(`returns true if the placeholder is found`, () => {
      const hasPlaceholder = urlHasLanguagePlaceholder(URL_WITH_PLACEHOLDER);

      expect(hasPlaceholder).toBeTruthy();
    });

    it(`returns false if the placeholder is not present`, () => {
      const hasPlaceholder = urlHasLanguagePlaceholder(URL_WITHOUT_PLACEHOLDER);

      expect(hasPlaceholder).toBeFalsy();
    });

    it(`returns false if the placeholder is misspelled`, () => {
      const hasPlaceholder = urlHasLanguagePlaceholder(URL_WITH_MISSPELLED_PLACEHOLDER);

      expect(hasPlaceholder).toBeFalsy();
    });
  });

  describe(getTranslatedLink.name, () => {
    it(`gets the translated link using the shortened language code, en`, () => {
      const translatedLink = getTranslatedLink(URL_WITH_PLACEHOLDER, `en`);

      expect(translatedLink).toEqual(URL_EN);
    });

    it(`gets the translated link using the shortened language code, es`, () => {
      const translatedLink = getTranslatedLink(URL_WITH_PLACEHOLDER, `es`);

      expect(translatedLink).toEqual(URL_ES);
    });

    it(`gets the translated link using the longer language code, "english"`, () => {
      const translatedLink = getTranslatedLink(URL_WITH_QUERY_PARAM_PLACEHOLDER, `english`);

      expect(translatedLink).toEqual(URL_ENGLISH);
    });
  });

  describe(`parseHttpsUrl`, () => {
    it(`returns a URL for an https url`, () => {
      const result = parseHttpsUrl(`https://www.in.gov/dor/`);

      expect(result).not.toBeNull();
      expect(result?.protocol).toBe(`https:`);
      expect(result?.host).toBe(`www.in.gov`);
    });

    it(`returns null for a javascript: url`, () => {
      expect(parseHttpsUrl(`javascript:alert(1)`)).toBeNull();
    });

    it(`returns null for a data: url`, () => {
      expect(parseHttpsUrl(`data:text/html,<script>alert(1)</script>`)).toBeNull();
    });

    it(`returns null for an http url`, () => {
      expect(parseHttpsUrl(`http://www.in.gov/dor/`)).toBeNull();
    });

    it(`returns null for an unparseable string`, () => {
      expect(parseHttpsUrl(`not a url`)).toBeNull();
    });

    it(`returns null for null, undefined, and empty string`, () => {
      expect(parseHttpsUrl(null)).toBeNull();
      expect(parseHttpsUrl(undefined)).toBeNull();
      expect(parseHttpsUrl(``)).toBeNull();
    });

    it(`returns a distinct URL object the caller can mutate safely`, () => {
      const result = parseHttpsUrl(`https://www.in.gov/dor/`);
      result?.searchParams.append(`ref`, `df`);

      expect(result?.toString()).toBe(`https://www.in.gov/dor/?ref=df`);
    });
  });
});
