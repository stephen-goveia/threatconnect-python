""" standard """
from datetime import datetime

""" custom """
from examples.working_init import *
from threatconnect.Config.FilterOperator import FilterOperator
from threatconnect.Config.IndicatorType import IndicatorType
from threatconnect.Config.ResourceType import ResourceType

""" Working with Indicators """

""" Toggle the Boolean to enable specific examples """
enable_example1 = False
enable_example2 = False
enable_example3 = False
enable_example4 = False
enable_example5 = False
owners = ['Example Community']


# shared method to display results from examples below
def show_data(result_obj):
    """  """
    if result_obj.get_status().name == "SUCCESS":
        for obj in result_obj:
            print('\n{:_^80}'.format(obj.get_indicator()))
            print('{:<20}{:<50}'.format('ID', obj.get_id()))
            print('{:<20}{:<50}'.format('Owner Name', obj.get_owner_name()))
            print('{:<20}{:<50}'.format('Date Added', obj.get_date_added()))
            print('{:<20}{:<50}'.format('Web Link', obj.get_web_link()))

            #
            # resource attributes
            #
            print('\n{:-^40}'.format(' Attributes '))
            result_obj.get_attributes(obj)
            for attr_obj in obj.attribute_objects:
                print('{:<20}{:<50}'.format('  Type', attr_obj.get_type()))
                print('{:<20}{:<50}'.format('  Value', attr_obj.get_value()))
                print('{:<20}{:<50}\n'.format('  Date Added', attr_obj.get_date_added()))

            #
            # resource tags
            #
            print('\n{:-^40}'.format(' Tags '))
            result_obj.get_tags(obj)
            for tag_obj in obj.tag_objects:
                print('{:<20}{:<50}'.format('  Name', tag_obj.get_name()))
                print('{:<20}{:<50}\n'.format('  Web Link', tag_obj.get_web_link()))

            #
            # resource associations (indicators)
            #
            print('\n{:-^40}'.format(' Indicator Associations '))
            result_obj.get_indicator_associations(obj)
            for i_associations in obj.association_objects_indicators:
                print('{:<20}{:<50}'.format('  ID', i_associations.get_id()))
                print('{:<20}{:<50}'.format('  Indicator', i_associations.get_indicator()))
                print('{:<20}{:<50}'.format('  Type', i_associations.get_type()))
                print('{:<20}{:<50}'.format('  Description', i_associations.get_description()))
                print('{:<20}{:<50}'.format('  Owner', i_associations.get_owner_name()))
                print('{:<20}{:<50}'.format('  Rating', i_associations.get_rating()))
                print('{:<20}{:<50}'.format('  Confidence', i_associations.get_confidence()))
                print('{:<20}{:<50}'.format('  Date Added', i_associations.get_date_added()))
                print('{:<20}{:<50}'.format('  Last Modified', i_associations.get_last_modified()))
                print('{:<20}{:<50}\n'.format('  Web Link', i_associations.get_web_link()))

            #
            # resource associations (groups)
            #
            print('\n{:-^40}'.format(' Group Associations '))
            result_obj.get_group_associations(obj, ResourceType.ADVERSARIES)
            for g_associations in obj.association_objects_groups:
                print('{:<20}{:<50}'.format('  ID', g_associations.get_id()))
                print('{:<20}{:<50}'.format('  Name', g_associations.get_name()))
                if hasattr(g_associations, 'get_type'):
                    print('{:<20}{:<50}'.format('  Type', g_associations.get_type()))
                print('{:<20}{:<50}'.format('  Owner Name', g_associations.get_owner_name()))
                print('{:<20}{:<50}'.format('  Date Added', g_associations.get_date_added()))
                print('{:<20}{:<50}\n'.format('  Web Link', g_associations.get_web_link()))

    #
    # print report
    #
    print(tc.report.stats)


def main():
    """ """
    # set threat connect log (tcl) level
    tc.set_tcl_file('log/tc.log')
    tc.set_tcl_console_level('critical')

    if enable_example1:
        """ This is a basic example that pull all indicators for the default org. """

        # optionally set max results
        tc.set_max_results(500)

        # indicator object
        indicators = tc.indicators()

        try:
            # retrieve indicators
            indicators.retrieve()
        except RuntimeError as e:
            print(e)
            sys.exit(1)

        # show indicator data
        show_data(indicators)

    if enable_example2:
        """ This example adds a filter for a particular owner (owners is a list of owners). """

        # optionally set max results
        tc.set_max_results(500)

        # indicator object
        indicators = tc.indicators()

        # optionally set modified since date
        # modified_since does not work with any filters other than owners
        modified_since = (datetime.isoformat(datetime(2015, 3, 20))) + 'Z'
        indicators.set_modified_since(modified_since)

        # get filter
        filter1 = indicators.add_filter()
        filter1.add_owner(owners)

        # check for any error on filter creation
        if filter1.error:
            for filter_error in filter1.get_errors():
                pd(filter_error)
            sys.exit(1)

        # retrieve indicators
        try:
            indicators.retrieve()
        except RuntimeError as e:
            print(e)
            sys.exit(1)

        # show indicator data
        show_data(indicators)

    if enable_example3:
        """ This example adds a filter to pull an indicator by indicator. """
        # optionally set max results
        tc.set_max_results(500)

        # indicator object
        indicators = tc.indicators()

        # get filter
        filter1 = indicators.add_filter()

        filter1.add_indicator('bigdocomojp.com')
        # filter1.add_indicator('4.3.2.1')
        # filter1.add_indicator('DCF06BCA3B1B87C8AF3289D0B42D8FE0')
        # filter1.add_indicator('bad_guy@badguysareus.com')
        # filter1.add_indicator('http://baddomain.badguysareus.com')

        # check for any error on filter creation
        if filter1.error:
            for filter_error in filter1.get_errors():
                pd(filter_error)
            sys.exit(1)

        try:
            # retrieve indicators
            indicators.retrieve()
        except RuntimeError as e:
            print(e)
            sys.exit(1)

        # show indicator data
        show_data(indicators)

    if enable_example4:
        """ This example adds a filter with multiple sub filters.  This request
            will return any indicators that matches any filters with the exception
            of post filters. """

        # optionally set max results
        tc.set_max_results(500)

        # indicator object
        indicators = tc.indicators()

        # get filter
        # filter1 = indicators.add_filter()
        filter1 = indicators.add_filter(IndicatorType.FILES)
        # filter1 = indicators.add_filter(IndicatorType.ADDRESSES)
        # filter1 = indicators.add_filter(IndicatorType.EMAIL_ADDRESSES)
        # filter1 = indicators.add_filter(IndicatorType.FILES)
        # filter1 = indicators.add_filter(IndicatorType.HOSTS)
        # filter1 = indicators.add_filter(IndicatorType.URLS)
        filter1.add_owner(owners)
        filter1.add_adversary_id(3)
        filter1.add_email_id(45621)
        filter1.add_incident_id(708917)
        filter1.add_incident_id(708996)
        filter1.add_security_label('DO NOT SHARE')
        filter1.add_signature_id(65646)
        filter1.add_tag('China')
        filter1.add_threat_id(146272)
        filter1.add_victim_id(369)

        filter1.add_pf_date_added('2014-04-10T00:00:00Z', FilterOperator.GE)
        filter1.add_pf_rating('2.5', FilterOperator.GE)
        filter1.add_pf_confidence(75, FilterOperator.GE)

        # check for any error on filter creation
        if filter1.error:
            for filter_error in filter1.get_errors():
                pd(filter_error)
            sys.exit(1)

        try:
            # retrieve indicators
            indicators.retrieve()
        except RuntimeError as e:
            print(e)
            sys.exit(1)

        # show indicator data
        show_data(indicators)

    if enable_example5:
        """ This example adds multiple filters to limit the result set.  This request
            will return only indicators that match all filters. """

        # optionally set max results
        tc.set_max_results(500)

        # indicator object
        indicators = tc.indicators()

        # get filter
        filter1 = indicators.add_filter()
        filter1.add_owner(owners)
        filter1.add_security_label('APPROVED FOR RELEASE')

        # check for any error on filter creation
        if filter1.error:
            for filter_error in filter1.get_errors():
                pd(filter_error)
            sys.exit(1)

        filter2 = indicators.add_filter()
        filter2.add_filter_operator(FilterSetOperator.AND)
        filter2.add_threat_id(146272)

        # check for any error on filter creation
        if filter2.error:
            for filter_error in filter2.get_errors():
                pd(filter_error)
            sys.exit(1)

        filter3 = indicators.add_filter(IndicatorType.ADDRESSES)
        filter3.add_filter_operator(FilterSetOperator.OR)
        filter3.add_tag('China')

        # check for any error on filter creation
        if filter3.error:
            for filter_error in filter3.get_errors():
                pd(filter_error)
            sys.exit(1)

        # retrieve indicators
        indicators.retrieve()

        # show indicator data
        show_data(indicators)

if __name__ == "__main__":
    main()
