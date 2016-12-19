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
from threatconnect.IndicatorObjectTyped import CustomIndicatorField

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

owner = 'System'  # org or community
rn = randint(1, 100)  # random number generator for testing


def main():
    """ """
    # set threat connect log (tcl) level
    tc.set_tcl_file('log/tc.log', 'debug')
    tc.set_tcl_console_level('critical')
    tc.report_enable()

    # (Required) Instantiate a Resource Object
    resources = tc.indicators()

    try:
        resources.retrieve()
    except RuntimeError as e:
        print('Error: {0!s}'.format(e))
        sys.exit(1)

    print "# of indicators retrieved: {}".format(len(resources))

    resources.add_custom_type('Mutex', 'mutexes', 'mutex', field1='key1')

    i_ordered_dict = OrderedDict()
    i_ordered_dict['Fruit'] = 'fruit?'


    known_resource = resources.add('1.0.0.1', owner=owner, type=IndicatorType.ADDRESSES)
    resource = resources.add(i_ordered_dict, owner=owner, type=IndicatorType.CUSTOM_INDICATORS, api_branch='fruits')



    # custom_indicators_commit

    try:
        print('Adding known resource {0!s}.'.format(known_resource.indicator))
        known_resource.commit()
        print('Adding resource {0!s}.'.format(resource.indicator))
        resource.commit()
    except RuntimeError as e:
        print('Error: {0!s}'.format(e))
        sys.exit(1)

    resource.set_confidence(rn)
    resource.set_rating(randint(1, 5))

    try:
        print('Updating resource {0!s}.'.format(resource.indicator))
        resource.commit()
    except RuntimeError as e:
        print('Error: {0!s}'.format(e))
        sys.exit(1)

if __name__ == "__main__":
    main()
    sys.exit()