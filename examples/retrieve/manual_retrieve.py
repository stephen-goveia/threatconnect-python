""" standard """
from pprint import pprint
import json

""" custom """
from examples.working_init import *
from threatconnect.RequestObject import RequestObject

""" Toggle the Boolean to enable specific examples """
enable_example1 = False
enable_example2 = True

if enable_example1:
    #
    # build INDICATORS request object
    #
    ro = RequestObject()
    ro.set_http_method('GET')
    ro.set_owner('Example Community')
    ro.set_owner_allowed(True)
    ro.set_resource_pagination(True)
    ro.set_request_uri('/v2/indicators')

    #
    # retrieve and display the results
    #
    results = tc.api_request(ro)
    if results.headers['content-type'] == 'application/json':
        data = results.json()
        print(json.dumps(data, indent=4))

if enable_example2:
    #
    # build DOCUMENT DOWNLOAD request object
    #
    ro = RequestObject()
    ro.set_http_method('GET')
    ro.set_owner('Example Community')
    ro.set_owner_allowed(True)
    ro.set_resource_pagination(False)
    ro.set_request_uri('/v2/groups/documents/19/download')

    #
    # retrieve and display the results
    #
    results = tc.api_request(ro)
    if results.headers['content-type'] == 'application/octet-stream':
        file_contents = results.content
        print(file_contents)
