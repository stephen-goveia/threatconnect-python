from examples.working_init import *

""" Working with Groups """

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
            print('\n{:_^80}'.format(obj.get_name()))
            print('{:<20}{:<50}'.format('ID', obj.get_id()))
            print('{:<20}{:<50}'.format('Owner Name', obj.get_owner_name()))
            print('{:<20}{:<50}'.format('Date Added', obj.get_date_added()))
            print('{:<20}{:<50}'.format('Web Link', obj.get_web_link()))

    #
    # print report
    #
    print(tc.report.stats)


def main():
    """  """
    # set threat connect log (tcl) level
    tc.set_tcl_file('log/tc.log')
    tc.set_tcl_console_level('critical')

    if enable_example1:
        """ This is a basic example that pull all groups for the default org. """

        # optionally set max results
        tc.set_max_results(500)

        # group object
        groups = tc.groups()

        # retrieve indicators
        groups.retrieve()

        # show indicator data
        show_data(groups)

    if enable_example2:
        """ This example adds a filter for a particular owner (owners is a list of owners). """

        # optionally set max results
        tc.set_max_results(500)

        # group object
        groups = tc.groups()

        # get filter
        filter1 = groups.add_filter()
        filter1.add_owner(owners)

        # check for any error on filter creation
        if filter1.error:
            for error in filter1.get_errors():
                pd(error)
            sys.exit(1)

        # retrieve indicators
        groups.retrieve()

        # show indicator data
        show_data(groups)

    if enable_example3:
        """ This example adds a filter to pull an groups by id. """

        # optionally set max results
        tc.set_max_results(500)

        # group object
        groups = tc.groups()

        # get filter
        filter1 = groups.add_filter()
        filter1.add_owner(owners)
        filter1.add_email_id(17)

        # check for any error on filter creation
        if filter1.error:
            for error in filter1.get_errors():
                pd(error)
            sys.exit(1)

        # retrieve indicators
        groups.retrieve()

        # show indicator data
        show_data(groups)

    if enable_example4:
        """ This example adds a filter with multiple sub filters.  This request
            will return any groups that matches any filters. """

        # optionally set max results
        tc.set_max_results(500)

        # group object
        groups = tc.groups()

        # get filter
        filter1 = groups.add_filter()
        filter1.add_owner(owners)
        filter1.add_incident_id(6)
        filter1.add_indicator('bad_guy@badguysareus.com')
        filter1.add_security_label('TLP Green')
        filter1.add_tag('EXAMPLE')
        filter1.add_threat_id(747243)
        filter1.add_email_id(747227)
        filter1.add_signature_id(747239)
        filter1.add_victim_id(628)

        # check for any error on filter creation
        if filter1.error:
            for error in filter1.get_errors():
                pd(error)
            sys.exit(1)

        # retrieve indicators
        groups.retrieve()

        # show indicator data
        show_data(groups)

    if enable_example5:
        """ This example adds multiple filters to limit the result set.  This request
            will return only groups that match all filters. """

        # optionally set max results
        tc.set_max_results(500)

        # group object
        groups = tc.groups()

        # get filter
        filter1 = groups.add_filter()
        filter1.add_owner(owners)
        filter1.add_tag('EXAMPLE')

        # check for any error on filter creation
        if filter1.error:
            for error in filter1.get_errors():
                pd(error)
            sys.exit(1)

        filter2 = groups.add_filter()
        filter2.add_owner(owners)
        filter2.add_indicator('bad_guy@badguysareus.com')

        # check for any error on filter creation
        if filter2.error:
            for error in filter1.get_errors():
                pd(error)
            sys.exit(1)

        # retrieve indicators
        groups.retrieve()

        # show indicator data
        show_data(groups)

if __name__ == "__main__":
    main()
