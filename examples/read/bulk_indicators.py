""" standard """
from datetime import datetime
from threatconnect.Config.FilterOperator import FilterOperator

""" custom """
from examples.working_init import *

""" Working with Indicators """

""" Toggle the Boolean to enable specific examples """
enable_example1 = False
enable_example2 = True
enable_example3 = False


def show_data(result_obj):
    """  """
    print('Status: {0}'.format(result_obj.get_status().name))
    print('Length: {0}'.format(len(result_obj)))
    if result_obj.get_status().name == "SUCCESS":
        for obj in result_obj:
            #
            # print object
            #
            print(obj)

            #
            # print attribute
            #
            for attribute_obj in obj.attribute_objects:
                print(attribute_obj)

            #
            # print tags
            #
            for tag_obj in obj.tag_objects:
                print(tag_obj)

    print(tc.report.stats)


def main():
    """ """
    # set threat connect log (tcl) level
    tc.set_tcl_file('log/tc.log', 'critical')
    tc.set_tcl_console_level('critical')

    # owners = ['Common Community']
    owners = ['Blocklist.de Source', 'ZeuS Tracker Source', 'MalwareDomainList Source']
    # owners = ['Test Community']
    # owners = ['ImportTest']

    if enable_example1:
        """ get community/source status """

        # optionally set max results
        tc.set_max_results(500)

        # indicator object
        bulk = tc.bulk()
        filter1 = bulk.add_filter()
        filter1.add_owner(owners)

        # retrieve indicators
        bulk.retrieve()

        # show indicator data
        show_data(bulk)

    if enable_example2:
        """ get bulk indicators """

        # optionally set max results
        tc.set_max_results(500)

        # indicator object
        indicators = tc.bulk_indicators()
        filter1 = indicators.add_filter()
        filter1.add_owner(owners)
        filter1.set_format('json')
        filter1.add_pf_confidence(1, FilterOperator.GE)
        # filter1.add_pf_date_added('2014-04-10T00:00:00Z', FilterOperator.GE)
        # filter1.add_pf_rating('4.0', FilterOperator.GE)
        # filter1.add_pf_type('Host')
        # filter1.add_pf_last_modified('2015-01-21T00:31:44Z', FilterOperator.LE)
        # filter1.add_pf_threat_assess_confidence('95', FilterOperator.GE)
        # filter1.add_pf_threat_assess_rating('4.0', FilterOperator.GE)
        # filter1.add_pf_tag('ImportTest', FilterOperator.EQ)
        # filter1.add_pf_attribute('Description', FilterOperator.EQ)

        # retrieve indicators
        indicators.retrieve()

        print(tc.report.stats)

        # show indicator data
        # show_data(indicators)
        # for row in indicators.csv:
        #     print(row)

    if enable_example3:
        """ get bulk indicators csv format """

        # the only supported filters on csv format are:
        # confidence
        # rating
        # type

        # optionally set max results
        tc.set_max_results(500)

        # indicator object
        indicators = tc.bulk_indicators()
        filter1 = indicators.add_filter()
        filter1.add_owner(owners)
        filter1.set_format('csv')
        filter1.add_pf_confidence(50, FilterOperator.GE)
        filter1.add_pf_rating('2.0', FilterOperator.GT)
        filter1.add_pf_type('Host')

        # retrieve indicators
        indicators.retrieve()

        # show indicator data
        show_data(indicators)

if __name__ == "__main__":
    main()
