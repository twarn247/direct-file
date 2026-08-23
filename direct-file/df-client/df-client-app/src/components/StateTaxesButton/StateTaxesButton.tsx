import LoadingIndicator from '../LoadingIndicator/LoadingIndicator.js';
import { useTranslation } from 'react-i18next';
import { Path } from '../../flow/Path.js';
import useFact from '../../hooks/useFact.js';
import useFetchStateProfile from '../../hooks/useFetchStateProfile.js';
import { CommonLinkRenderer } from 'df-common-link-renderer';
import { REF_LOCATION, REF_LOCATION_VALUE } from '../../constants/pageConstants.js';
import { parseHttpsUrl } from '../../utils/urlUtils.js';

const addQueryParams = (landingUrl: string): string | null => {
  const asUrl = parseHttpsUrl(landingUrl);
  if (asUrl === null) {
    return null;
  }
  asUrl.searchParams.append(REF_LOCATION, REF_LOCATION_VALUE.SUBMISSION);
  return asUrl.toString();
};

const StateTaxesButton = () => {
  const { t } = useTranslation(`translation`);
  const { stateProfile, isFetching } = useFetchStateProfile();

  const [scopedStateDoesNotHavePersonalIncomeTax] = useFact<boolean>(
    Path.concretePath(`/scopedStateDoesNotHavePersonalIncomeTax`, null)
  );

  if (isFetching) {
    return <LoadingIndicator />;
  }

  if (stateProfile) {
    const { landingUrl } = stateProfile;
    const landingUrlWithQueryParams = addQueryParams(landingUrl);
    if (landingUrlWithQueryParams === null) {
      return null;
    }

    if (scopedStateDoesNotHavePersonalIncomeTax) {
      return (
        <CommonLinkRenderer className='usa-button' url={landingUrlWithQueryParams}>
          {t(`stateInfoAlert.otherBenefit.linkText`)}
        </CommonLinkRenderer>
      );
    }

    return (
      <CommonLinkRenderer className='usa-button' url={landingUrlWithQueryParams}>
        {t(`stateInfoAlert.incomeTaxes.linkText`)}
      </CommonLinkRenderer>
    );
  } else {
    return null;
  }
};

export default StateTaxesButton;
