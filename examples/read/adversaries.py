from examples.working_init import *

""" Working with Adversaries """

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
            result_obj.get_group_associations(obj)
            for g_associations in obj.association_objects_groups:
                print('{:<20}{:<50}'.format('  ID', g_associations.get_id()))
                print('{:<20}{:<50}'.format('  Name', g_associations.get_name()))
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
        """ This is a basic example that pull all adversaries for the default org. """

        # optionally set max results
        tc.set_max_results(500)

        # adversary object
        adversaries = Adversaries(tc).retrieve()

        # show indicator data
        show_data(adversaries)

    if enable_example2:
        """ This example adds a filter for a particular owner (owners is a list of owners). """

        # optionally set max results
        tc.set_max_results(500)

        # adversary object
        adversaries = tc.adversaries()

        # get filter
        filter1 = adversaries.add_filter()
        filter1.add_owner(owners)

        # check for any error on filter creation
        if filter1.error:
            for error in filter1.get_errors():
                pd(error)
            sys.exit(1)

        # retrieve indicators
        adversaries.retrieve()

        # show indicator data
        show_data(adversaries)

    if enable_example3:
        """ This example adds a filter to pull an adversary by id. """
        # optionally set max results
        tc.set_max_results(500)

        # adversary object
        adversaries = tc.adversaries()

        # get filter
        filter1 = adversaries.add_filter()
        filter1.add_owner(owners)
        filter1.add_id(6)

        # check for any error on filter creation
        if filter1.error:
            for error in filter1.get_errors():
                pd(error)
            sys.exit(1)

        # retrieve indicators
        try:
            adversaries.retrieve()
        except RuntimeError as e:
            print(e)

        # show indicator data
        show_data(adversaries)

    if enable_example4:
        """ This example adds a filter with multiple sub filters.  This request
            will return any adversaries that matches any filters. """

        # optionally set max results
        tc.set_max_results(500)

        # adversary object
        adversaries = tc.adversaries()

        # get filter
        filter1 = adversaries.add_filter()
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
        adversaries.retrieve()

        # show indicator data
        show_data(adversaries)

    if enable_example5:
        """ This example adds multiple filters to limit the result set.  This request
            will return only adversaries that match all filters. """

        # optionally set max results
        tc.set_max_results(500)

        # adversary object
        adversaries = tc.adversaries()

        # get filter
        filter1 = adversaries.add_filter()
        filter1.add_owner(owners)
        filter1.add_tag('EXAMPLE')

        # check for any error on filter creation
        if filter1.error:
            for error in filter1.get_errors():
                pd(error)
            sys.exit(1)

        filter2 = adversaries.add_filter()
        filter2.add_filter_operator(FilterSetOperator.AND)
        filter2.add_owner(owners)
        filter2.add_indicator('4.3.2.1')

        # check for any error on filter creation
        if filter2.error:
            for error in filter2.get_errors():
                pd(error)
            sys.exit(1)

        # retrieve indicators
        adversaries.retrieve()

        # show indicator data
        show_data(adversaries)

if __name__ == "__main__":
    main()