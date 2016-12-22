

""" standard """
from collections import OrderedDict
import ConfigParser
from datetime import datetime
from random import randint
import re
import sys

""" custom """
from threatconnect import ThreatConnect
from threatconnect.Config.IndicatorType import IndicatorType
from threatconnect import FilterOperator
# from threatconnect.IndicatorObjectTyped import CustomIndicatorField

# configuration file
config_file = "tc.conf"

# retrieve configuration file
config = ConfigParser.RawConfigParser()
config.read(config_file)

try:
    api_access_id = config.get('threatconnect', 'api_access_id')
    api_secret_key = config.get('threatconnect', 'api_secret_key')
    api_default_org = config.get('threatconnect', 'api_default_org')
    api_base_url = config.get('threatconnect', 'api_base_url')
    api_result_limit = int(config.get('threatconnect', 'api_result_limit'))
except ConfigParser.NoOptionError:
    print('Could not retrieve configuration file.')
    sys.exit(1)

tc = ThreatConnect(api_access_id, api_secret_key, api_default_org, api_base_url)
tc.set_api_result_limit(api_result_limit)
tc.report_enable()

owner = 'CustomTest'  # org or community
rn = randint(1, 100)  # random number generator for testing


def main():
    """ """
    # set threat connect log (tcl) level
    tc.set_tcl_file('log/tc.log', 'debug')
    tc.set_tcl_console_level('critical')
    tc.report_enable()

    # (Required) Instantiate a Resource Object
    # resources = tc.indicators()
    #
    # filter1 = resources.add_filter(IndicatorType.CUSTOM_INDICATORS, api_entity='fruit')
    #
    # try:
    #     resources.retrieve()
    # except RuntimeError as e:
    #     print('Error: {0!s}'.format(e))
    #     sys.exit(1)
    #
    # print "# of indicators retrieved: {}".format(len(resources))
    #
    # fruit = OrderedDict()
    # fruit['size'] = 'medium-big'
    # fruit['shape'] = 'circle'
    #
    # fruit2 = OrderedDict()
    # fruit2['size'] = 'small-big'
    # fruit2['shape'] = 'circle'
    #
    # resources = tc.indicators()
    # print "TAG IDX: {}".format(resources._tag_idx)
    #
    # try:
    #     resource = resources.add(fruit, owner=owner, type=IndicatorType.CUSTOM_INDICATORS, api_entity='fruit')
    #     resource.set_confidence(0)
    #     resource.add_tag('CIRCULAR')
    #     resource.commit()
    #     print "TAG IDX: {}".format(resources._tag_idx)
    #
    #
    #     resource2 = resources.add(fruit2, owner='CustomTest', type=IndicatorType.CUSTOM_INDICATORS, api_entity='fruit')
    #     resource2.add_tag('OVULAR')
    #     resource2.commit()
    #     print "TAG IDX: {}".format(resources._tag_idx)
    #
    # except RuntimeError as e:
    #     print('Error: {0!s}'.format(e))
    #     sys.exit(1)
    #
    # resources = tc.bulk_indicators(on_demand=True)







    # filter2 = resources.add_filter(IndicatorType.CUSTOM_INDICATORS, api_entity='fruit')
    # filter2.add_pf_tag('CIRCULAR')
    # filter2.add_tag('OVULAR')
    # filter2.add_owner('CustomTest')
    # filter2.add_pf_threat_assess_rating(4)
    # filter2.add_pf_tag('CIRCULAR', FilterOperator.NE)
    # filter2.add_pf_tag('CIRCULAR', FilterOper ator.EQ)

    # try:
    #     resources.retrieve()
    #     # print "TAG IDX: {}".format(resources._tag_idx)
    #
    #     tags = 0
    #     for resource in resources:
    #         print "LOADING: {}".format(resource.indicator)
    #         resource.load_tags()
    #         tags = tags + len(resource.tags)
    #
    # except RuntimeError as e:
    #     print('Error: {0!s}'.format(e))
    #     sys.exit(1)
    #
    # print "==================\n# of indicators retrieved with tag filter: {}\n==================".format(len(resources))
    # print "Pre-filter: {}\nPost-filter: {}".format(fruit, resource.custom_fields)
    #
    # resources = tc.indicators()
    # pf_filter = resources.add_filter(IndicatorType.CUSTOM_INDICATORS, api_entity='fruit')
    # pf_filter.add_pf_type('Fruit', FilterOperator.NE)
    #
    # resources.retrieve()
    #
    # print "after pf filter"
    # print "# of indicators retrieved: {}".format(len(resources))
    #
    # resource.delete()
    #
    bulk_resources = tc.bulk_indicators(on_demand=True)

    # bulk_resources = tc.indicators()
    try:
        bulk_resources.retrieve()
        # print "TAG IDX: {}".format(resources._tag_idx)

        tags = 0
        for resource in bulk_resources:
            x = resource
            if not resource.indicator:
                pass
            print "LOADING: {}".format(resource.indicator)
            # resource.load_tags()
            # tags = tags + len(resource.tags)

    except RuntimeError as e:
        print('Error: {0!s}'.format(e))
        sys.exit(1)

    # bulk_filter = bulk_resources.add_filter(IndicatorType.CUSTOM_INDICATORS)


if __name__ == "__main__":
    main()
    sys.exit()