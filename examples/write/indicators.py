""" standard """
from random import randint
import re
import sys

""" custom """
from examples.working_init import *

#
# CHANGE FOR YOUR TESTING ENVIRONMENT
# - These indicators must be created before running this script
#
owners = ['Example Community']  # org or community
lu_indicator = '10.20.30.40'  # indicators for loop update
mu_indicator = '40.20.30.10'  # indicators id for manual update
# dl_id = 999999  # indicator id to delete
adversary_id = 5  # email resource id to associate with indicator
rn = randint(1, 100)  # random number generator for testing


def main():
    """ """
    # set threat connect log (tcl) level
    tc.set_tcl_file('log/tc.log', 'debug')
    tc.set_tcl_console_level('debug')

    # (Required) Instantiate a Resource Object
    resources = tc.indicators()

    # (Optional) Filters can be added here if required to narrow the result set.
    filter1 = resources.add_filter()
    filter1.add_owner(owners)

    # (Optional) retrieve all results
    resources.retrieve()

    # (Optional) iterate through all results if retrieve was used above
    for res in resources:

        # (Optional) match a particular resource by ID, Name or any other supported attribute.
        if res.get_indicator() == lu_indicator:
            #
            # update resource if required
            #
            res.set_confidence(rn)
            res.set_rating(randint(0, 5))

            #
            # working with indicator associations
            #

            # CAN pull indicator to indicator associations,
            # but CANNOT associate indicator with indicator

            #
            # working with group associations
            #

            # (Optional) get all group associations
            resources.get_group_associations(res)
            for association in res.association_objects_groups:
                # add delete flag to all group association that match DELETE
                if re.findall('Loop', association.get_name()):
                    res.disassociate(association.resource_type, association.get_id())

            res.associate(ResourceType.ADVERSARIES, adversary_id)

            #
            # working with victim associations
            #

            # (Optional) get all victim associations
            # resources.get_victim_associations(res)
            # for association in res.association_objects_victims:
            #     print(association)

            #
            # working with attributes
            #
            # (Optional) get all attributes associated with this resource
            resources.get_attributes(res)
            for attribute in res.attribute_objects:
                # add delete flag to all attributes that have 'test' in the value.
                if re.findall('test', attribute.get_value()):
                    res.delete_attribute(attribute.get_id())
                # add update flag to all attributes that have 'update' in the value.
                if re.findall('update', attribute.get_value()):
                    res.update_attribute(attribute.get_id(), 'updated attribute %s' % rn)
            # (Optional) add attribute to resource with type and value
            res.add_attribute('Description', 'test attribute %s' % rn)

            #
            # working with tags
            #

            # (Optional) get all tags associated with this resource
            resources.get_tags(res)
            for tag in res.tag_objects:
                # add delete flag to all tags that have 'DELETE' in the name.
                if re.findall('DELETE', tag.get_name()):
                    res.delete_tag(tag.get_name())
            # (Optional) add tag to resource
            res.add_tag('DELETE {0}'.format(rn))

        #
        # delete resource
        #

        # (Optional) add delete flag to any resource that start with '4.3.254'.
        if re.findall('4.3.254', res.get_indicator()):
            res.delete()

    #
    # add resource if required
    #

    # this requires that the resource was instantiated at the beginning of the script.
    resource = resources.add('4.3.254.{0}'.format(randint(0, 254)))
    resource.set_confidence(rn)
    resource.set_rating('2.0')

    #
    # example file indicator
    #

    # resource = resources.add('ac11ba81f1dc6d3637589ffa04366599')
    # resource.set_sha1('bec530f8e0104d4521958309eb9852e073150ac1')
    # resource.set_sha256('22010a665da94445f5b505c828d532886541900373d29042cc46c3300a186e28')

    # (Optional) add attribute to newly created resource
    resource.add_attribute('Description', 'test attribute #{0}'.format(rn))

    # (Optional) add tag to newly created resource
    resource.add_tag('TAG #{0}'.format(rn))

    # (Required) commit all changes above.  No changes are made until the commit phase.
    try:
        resources.commit(owners)
    except RuntimeError as e:
        print(e)

    # (Optional) iterate through the result sets after changes.
    for res in resources:
        print(res)

    # (Optional) display a commit report of all API actions performed
    print(tc.report.stats)

    # display any failed api calls
    for fail in tc.report.failures:
        print(fail)

    from time import sleep
    sleep(5)
    print('-' * 80)

    # (Required) commit all changes above.  No changes are made until the commit phase.
    try:
        resources.commit(owners)
    except RuntimeError as e:
        print(e)


if __name__ == "__main__":
    main()
    sys.exit()
