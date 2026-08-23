export const LANGUAGE_CODE_PLACEHOLDER = `{LANGUAGE_CODE}`;

export const urlHasLanguagePlaceholder = (urlString: string): boolean => urlString.includes(LANGUAGE_CODE_PLACEHOLDER);

/**
 *
 * @param urlString
 * @param languageCode Potentially an external systems language identifier. Might be `en`, `en-US`, `english`, etc.
 */
export const getTranslatedLink = (urlString: string, languageCode: string) => {
  return urlString.replace(LANGUAGE_CODE_PLACEHOLDER, languageCode);
};

/**
 * Parses a URL supplied by a state partner's profile.
 *
 * State profile URLs (landingUrl, cancel URLs, redirect URLs) arrive from the
 * state-api database and are navigated to or rendered as links inside the
 * authenticated app. `new URL()` alone is not a safety check: it parses
 * `javascript:` and `data:` URLs, and navigating to those executes them.
 *
 * Returns null rather than throwing so callers degrade to not rendering the
 * link, instead of crashing the screen.
 */
export const parseHttpsUrl = (urlString: string | null | undefined): URL | null => {
  if (!urlString) {
    return null;
  }

  let url: URL;
  try {
    url = new URL(urlString);
  } catch {
    return null;
  }

  return url.protocol === `https:` ? url : null;
};
