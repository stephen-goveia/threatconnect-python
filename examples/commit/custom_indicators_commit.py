""" standard """
from collections import OrderedDict
import ConfigParser
from random import randint
import sys

""" custom """
from threatconnect import ThreatConnect
from threatconnect.Config.IndicatorType import IndicatorType

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

    # resources.add_custom_type('Mutex', 'mutexes', 'mutex', field1='key1')

    fruit = OrderedDict()
    fruit['size'] = 'large'
    fruit['shape'] = 'triangluar'
    resource = resources.add(fruit, owner=owner, type=IndicatorType.CUSTOM_INDICATORS, api_entity='fruit')

    known_resource = resources.add('0.1.1.0', owner=owner, type=IndicatorType.ADDRESSES)
    # known_resource2 = resources.add('0.2.2.0', owner=owner, type=IndicatorType.ADDRESSES)

    fruit_without_order = dict()
    fruit_without_order['size'] = 'petite'
    fruit_without_order['shape'] = 'rotund'
    resource_without_order = resources.add(fruit_without_order, owner=owner, type=IndicatorType.CUSTOM_INDICATORS, api_entity='fruit')


    # custom_indicators_commit

    try:
        print('Adding known resources {0!s}.'.format(known_resource.indicator))
        known_resource.commit()
        # known_resource2.commit()
        print('Adding resource {0!s}.'.format(resource.indicator))
        resource.commit()
        print('Adding resource without order {0!s}.'.format(resource_without_order.indicator))
        resource_without_order.commit()
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

    # known_resource.associate_group(ResourceType.ADDRESSES, '0.2.2.0')
    # known_resource.commit()
    # known_resource.associate_group(ResourceType.CUSTOM_INDICATORS, resource._reference_indicator, api_entity='fruit')
    # known_resource.commit()

    # print known_resource.indicator_associations

    try:
        print('Deleting resource {0!s}.'.format(resource.indicator))
        resource.delete()
        print('Deleting known_resource {0!s}.'.format(resource.indicator))
        known_resource.delete()
        print('Deleting resource_without_order {0!s}.'.format(resource.indicator))
        resource_without_order.delete()
    except RuntimeError as e:
        print('Error: {0!s}'.format(e))
        sys.exit(1)


if __name__ == "__main__":
    main()
    sys.exit()