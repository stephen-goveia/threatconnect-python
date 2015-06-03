""" standard """
from random import randint

""" custom """
from examples.working_init import *

#
# CHANGE FOR YOUR TESTING ENVIRONMENT
# - These adversaries must be created before running this script
#
owners = ['Example Community']  # org or community
lu_id = 5  # adversary id for loop update
mu_id = 6  # adversary id for manual update
# dl_id = 999999  # adversary id to delete
email_id = 17  # email resource id to associate with adversary
email_address = 'notsobad@gmail.com'  # email address to associate to adversary
rn = randint(1, 1000)  # random number generator for testing


def main():
    """ """
    # set threat connect log (tcl) level
    tc.set_tcl_file('log/tc.log', 'debug')
    tc.set_tcl_console_level('critical')

    # (Required) Instantiate a Resource Object
    resources = tc.adversaries()

    # (Optional) Filters can be added here if required to narrow the result set.
    filter1 = resources.add_filter()
    filter1.add_owner(owners)

    # (Optional) retrieve all results
    resources.retrieve()

    # (Optional) iterate through all results if retrieve was used above
    for res in resources:

        # (Optional) match a particular resource by ID, Name or any other supported attribute.
        if res.get_id() == lu_id:
            #
            # update resource if required
            #
            res.set_name('LU Adversary #{0}'.format(rn))

            #
            # working with indicator associations
            #

            # (Optional) get all indicator associations
            resources.get_indicator_associations(res)
            for association in res.association_objects_indicators:
                # add delete flag to all indicator association that have a confidence under 10
                if association.get_confidence() < 10:
                    res.disassociate(association.resource_type, association.get_indicator())

            # associate an indicator
            res.associate(ResourceType.EMAIL_ADDRESSES, email_address)

            #
            # working with group associations
            #

            # (Optional) get all group associations
            resources.get_group_associations(res)
            for association in res.association_objects_groups:
                # add delete flag to all group association that match DELETE
                if re.findall('Loop', association.get_name()):
                    res.disassociate(association.resource_type, association.get_id())

            # associate a group
            res.associate(ResourceType.EMAILS, email_id)

            #
            # working with victim associations
            #

            # (Optional) get all victim associations
            resources.get_victim_associations(res)
            for association in res.association_objects_victims:
                print(association)
                # add delete flag to all group association that match DELETE
                # if re.findall('Loop', association.get_name()):
                #     res.disassociate(association.resource_type, association.get_id())

            # res.associate(ResourceType.VICTIMS, 747266)

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
                    res.update_attribute(attribute.get_id(), 'updated attribute #{0}'.format(rn))
            # (Optional) add attribute to resource with type and value
            res.add_attribute('Description', 'test attribute #{0}'.format(rn))

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
            res.add_tag('DELETE #{0}'.format(rn))
        #
        # delete resource if required
        #

        # (Optional) add delete flag to any resource that has 'DELETE' in the name.
        if re.findall('DELETE', res.get_name()):
            res.delete()

    #
    # add resource if required (will be delete on next run)
    #
    resource = resources.add('DELETE #{0}'.format(rn))

    # (Optional) add attribute to newly created resource
    resource.add_attribute('Description', 'Delete Example #{0}'.format(rn))

    # (Optional) add tag to newly created resource
    resource.add_tag('TAG #{0}'.format(rn))

    # (Optional) add security label to newly created resource
    resource.add_security_label('TLP Green')

    #
    # update resource if required
    #

    # (Optional) a resource can be updated directly by using the resource id.
    resource = resources.update(mu_id)
    resource.set_name('MU Adversary #{0}'.format(rn))

    # (Optional) add attribute to newly created resource
    resource.add_attribute('Description', 'Manual Update Example #{0}'.format(rn))

    # (Optional) add tag to newly created resource
    resource.add_tag('TAG #{0}'.format(rn))

    #
    # delete resource
    #

    # (Optional) a resource can be deleted directly by using the resource id.
    # resources.delete(dl_id)

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


if __name__ == "__main__":
    main()
    sys.exit()
