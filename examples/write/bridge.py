""" standard """
import ConfigParser
import logging
from pprint import pprint
import sys

""" custom """
from threatconnect import *
from threatconnect.Config.ResourceType import ResourceType
from threatconnect.Validate import validate_indicator

# basic logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s %(levelname)s %(message)s',
    filename='import.log',
    filemode='w')

#
# read source configuration file (read instance of ThreatConnect)
#
src_config_file = "../tc.conf"
src_config = ConfigParser.RawConfigParser()
src_config.read(src_config_file)

try:
    src_api_access_id = src_config.get('threatconnect', 'api_access_id')
    src_api_secret_key = src_config.get('threatconnect', 'api_secret_key')
    src_api_default_org = src_config.get('threatconnect', 'api_default_org')
    src_api_base_url = src_config.get('threatconnect', 'api_base_url')
    src_api_max_results = src_config.get('threatconnect', 'api_max_results')
except ConfigParser.NoOptionError:
    print('Could not read source configuration file.')
    sys.exit(1)

src_tc = ThreatConnect(
    src_api_access_id, src_api_secret_key, src_api_default_org, src_api_base_url, src_api_max_results)
src_owners = ['Common Community']

#
# read destination configuration file (write instance of ThreatConnect)
#
dst_config_file = "../tc-local.conf"
dst_config = ConfigParser.RawConfigParser()
dst_config.read(dst_config_file)

try:
    dst_api_access_id = dst_config.get('threatconnect', 'api_access_id')
    dst_api_secret_key = dst_config.get('threatconnect', 'api_secret_key')
    dst_api_default_org = dst_config.get('threatconnect', 'api_default_org')
    dst_api_base_url = dst_config.get('threatconnect', 'api_base_url')
    dst_api_max_results = dst_config.get('threatconnect', 'api_max_results')
except ConfigParser.NoOptionError:
    print('Could not read source configuration file.')
    sys.exit(1)

dst_tc = ThreatConnect(
    dst_api_access_id, dst_api_secret_key, dst_api_default_org, dst_api_base_url, dst_api_max_results)
dst_owners = ['Common Community Local']

def main():
    """ """
    # destination resource object
    dst_indicators = dst_tc.indicators()

    """ get bulk indicators """

    # optionally set max results
    src_tc.set_max_results(500)

    # indicator object
    src_indicators = src_tc.bulk_indicators()
    filter1 = src_indicators.add_filter()
    filter1.add_owner(src_owners)
    filter1.set_format('json')

    #
    # Optional Post Filters
    #

    # filter1.add_pf_confidence(50, FilterOperator.GE)
    # filter1.add_pf_date_added('2014-04-10T00:00:00Z', FilterOperator.GE)
    # filter1.add_pf_rating('2.0', FilterOperator.GT)
    # filter1.add_pf_type('Host')
    # filter1.add_pf_last_modified('2015-01-21T00:31:44Z', FilterOperator.LE)
    # filter1.add_pf_threat_assess_confidence('95', FilterOperator.GE)
    # filter1.add_pf_threat_assess_rating('4.0', FilterOperator.GE)
    # filter1.add_pf_tag('China', FilterOperator.EQ)
    # filter1.add_pf_attribute('Description', FilterOperator.EQ)

    # retrieve indicators
    print('Retrieving Bulk Indicators ...')
    src_indicators.retrieve()
    print(src_tc.report.stats)

    print('Duplicating Indicators ...')
    if src_indicators.get_status().name == "SUCCESS":
        for obj in src_indicators:
            # log indicator
            logging.info('%s: %s', obj.resource_type.name.lower(), obj.get_indicator())

            #
            # add resource if required
            #
            indicator = dst_indicators.add(obj.get_indicator())

            if indicator is None:
                # logs
                logging.critical('Invalid Indicator: %s', obj)
                continue

            # TEMPORARILY ignore 0 until bug if fixed
            if obj.get_confidence() is not None and obj.get_confidence() > 0:
                indicator.set_confidence(obj.get_confidence())
            if obj.get_rating() is not None and obj.get_rating() > 0:
                indicator.set_rating(obj.get_rating())

            #
            # print attribute
            #
            for attribute_obj in obj.attribute_objects:
                # print(attribute_obj)
                indicator.add_attribute(attribute_obj.get_type(), attribute_obj.get_value())

            #
            # print tags
            #
            for tag_obj in obj.tag_objects:
                indicator.add_tag(tag_obj.get_name())

        print('\nCommitting ...')
        # (Required) commit all changes above.  No changes are made until the commit phase.
        dst_indicators.commit(dst_owners)

        #
        # Failures
        #
        for failure in dst_tc.report.failures:
            print(failure)
        print(dst_tc.report.stats)

if __name__ == "__main__":
    main()
