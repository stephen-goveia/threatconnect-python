""" standard """
from random import randint
import re

""" custom """
from examples.working_init import *

#
# CHANGE FOR YOUR TESTING ENVIRONMENT
# - These incidents must be created before running this script
#
owners = ['Example Community']  # org or community
lu_id = 34  # incident id for loop update
mu_id = 35  # incident id for manual update
# dl_id = 999999  # threat id to delete
adversary_id = 5  # adversary resource id to associate with incident
victim_id = 1  # victim resource id to associate with incident
ip_address = '10.20.30.40'  # email address to associate to adversary
rn = randint(1, 1000)  # random number generator for testing


def main():
    """ """
    # set threat connect log (tcl) level
    tc.set_tcl_file('log/tc.log', 'debug')
    tc.set_tcl_console_level('critical')

    # (Required) Instantiate a Resource Object
    resources = tc.incidents()


    #
    # update resource if required
    #

    # (Optional) a resource can be updated directly by using the resource id.
    resource = resources.update(mu_id)
    resource.associate(ResourceType.ADDRESSES, ip_address)

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

    for fail in tc.report.failures:
        print(fail)


if __name__ == "__main__":
    main()
