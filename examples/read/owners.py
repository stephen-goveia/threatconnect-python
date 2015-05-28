from examples.working_init import *

""" Get Owners """
enable_example1 = False
enable_example2 = False
enable_example3 = False


# shared method to display results from examples below
def show_data(result_obj):
    """  """
    if result_obj.get_status().name == "SUCCESS":
        for obj in result_obj:
            print('\n{:_^80}'.format(obj.get_name()))
            print('{:<20}{:<50}'.format('ID', obj.get_id()))
            print('{:<20}{:<50}'.format('Type', obj.get_type()))
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
        """ This is a basic example that pull all owners. """
        # optionally set the max results the api should return in one request
        tc.set_max_results(500)

        owners = tc.owners()
        owners.retrieve()
        show_data(owners)

    if enable_example2:
        """ This example retrieves all owners that a particular indicator appears. """

        # get owner object
        owners = tc.owners()

        # create a filter
        # If no indicator type is provided the indicator type will be automatically determined.
        filter1 = owners.add_filter()
        filter1.add_indicator('4.3.2.1')

        # check for any error on filter creation
        if filter1.error:
            for error in filter1.get_errors():
                pd(error)
            sys.exit(1)

        # retrieve owners
        owners.retrieve()

        show_data(owners)

    """
    Method:
    get_owners() ->  This method can be used to get a object containing owners filtered by indicator.
    """
    if enable_example3:

        # get owner object
        owners = tc.owners()

        # create a filter
        # If no indicator type is provided the indicator type will be automatically determined.
        filter1 = owners.add_filter()
        filter1.add_indicator('4.3.2.1')

        # check for any error on filter creation
        if filter1.error:
            for error in filter1.get_errors():
                pd(error)
            sys.exit(1)

        filter2 = owners.add_filter()
        filter2.add_filter_operator(FilterSetOperator.AND)
        filter2.add_indicator('bad_guy@badguysareus.com')

        # check for any error on filter creation
        if filter2.error:
            for error in filter2.get_errors():
                pd(error)
            sys.exit(1)

        owners.retrieve()
        show_data(owners)

if __name__ == "__main__":
    main()
