""" standard """
from random import randint
import re

""" custom """
from examples.working_init import *

#
# CHANGE FOR YOUR TESTING ENVIRONMENT
# - These documents must be created before running this script
#
owners = ['Example Community']  # org or community
lu_id = 19  # document id for loop update
mu_id = 21  # document id for manual update
# dl_id = 999999  # threat id to delete
adversary_id = 5  # adversary resource id to associate with document
email_address = 'notsobad@gmail.com'  # email address to associate to document
rn = randint(1, 1000)  # random number generator for testing


def main():
    """ """
    # set threat connect log (tcl) level
    tc.set_tcl_file('log/tc.log', 'debug')
    tc.set_tcl_console_level('critical')

    # (Required) Instantiate a Resource Object
    resources = tc.documents()

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
            res.set_name('LU Document #{0}'.format(rn))
            res.set_file_name('Loop Update {0}.txt'.format(rn))
            data = 'Loop update file content #{0}.'.format(rn)
            res.upload(data, True)

            #
            # working with indicator associations
            #

            # (Optional) get all indicator associations
            # resources.get_indicator_associations(res)
            resources.get_indicator_associations(res, IndicatorType.EMAIL_ADDRESSES)
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
            res.associate(ResourceType.ADVERSARIES, adversary_id)

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
        # download document
        #
        if res.get_id() == mu_id:
            res.download()

        #
        # delete resource if required
        #

        # (Optional) add delete flag to any resource that has 'DELETE' in the name.
        if re.findall('DELETE', res.get_name()):
            res.delete()

    #
    # add resource if required
    #

    # this requires that the resource was instantiated at the beginning of the script.
    resource = resources.add('DELETE #{0}'.format(rn))
    # (Required) all required attributes must be provided.
    resource.set_file_name('New File {0}.txt'.format(rn))
    data = 'This is a newly created file content #{0}.'.format(rn)
    resource.upload(data)

    # (Optional) add attribute to newly created resource
    resource.add_attribute('Description', 'Attribute to delete #{0}'.format(rn))

    # (Optional) add tag to newly created resource
    resource.add_tag('TAG #{0}'.format(rn))

    #
    # update resource if required
    #

    # (Optional) a resource can be updated directly by using the resource id.
    resource = resources.update(mu_id)
    resource.set_name('MU Document #{0}'.format(rn))
    resource.set_file_name('Manual Update {0}.txt'.format(rn))
    # data = open('./sample_upload.txt', 'rb').read()
    data = 'Manual update file content #{0}.'.format(rn)
    resource.upload(data, True)

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
        if res.get_id() == mu_id:
            # (Optional) write the document out to a file
            print(res.get_file_name())
            print(res.document)

    # (Optional) display a commit report of all API actions performed
    print(tc.report.stats)

    for fail in tc.report.failures:
        print(fail)

    # for rpt in tc.report:
    #     print(rpt)

if __name__ == "__main__":
    main()
