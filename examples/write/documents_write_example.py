""" standard """
import sys

""" custom """
from examples.working_init import *

enable_add = True
enable_upd = True
enable_del = True


def main():
    """ """
    resources = tc.documents()
    resource_id = None

    if enable_add:
        """ """
        resource = resources.add_resource('bcs bad doc')
        resource.set_file_name('bcs.doc')
        resources.send()

        for res in resources:
            print(res)
            resource_id = res.get_id()

    if enable_upd:
        """ """
        resource = resources.update(resource_id)
        resource.set_name('bcs really bad doc')
        resource.set_file_name('bcs.docx')
        resources.send()

    if enable_del:
        resources.delete(resource_id)

if __name__ == "__main__":
    main()