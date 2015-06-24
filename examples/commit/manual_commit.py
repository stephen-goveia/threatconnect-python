""" standard """
from pprint import pprint
import json

""" custom """
from examples.working_init import *
from threatconnect.RequestObject import RequestObject

""" Toggle the Boolean to enable specific examples """
enable_example1 = True
enable_example2 = False

if enable_example1:
    #
    # build DOCUMENT request object
    #
    ro = RequestObject()
    ro.set_http_method('POST')
    body = {'name': 'Raw Upload Example', 'fileName': 'raw_example.txt'}
    ro.set_body(json.dumps(body))
    ro.set_content_type('application/json')
    ro.set_owner('Example Community')
    ro.set_owner_allowed(True)
    ro.set_resource_pagination(False)
    ro.set_request_uri('/v2/groups/documents')

    # display request object parameters
    print(ro)

    #
    # retrieve and display the results
    #
    results = tc.api_request(ro)
    if results.headers['content-type'] == 'application/json':
        data = results.json()
        print(json.dumps(data, indent=4))

        document_id = data['data']['document']['id']

        #
        # build DOCUMENT UPLOAD request object
        #
        ro = RequestObject()
        ro.set_http_method('POST')
        body = 'Raw upload example file Contents.'
        ro.set_body(body)
        ro.set_content_type('application/octet-stream')
        ro.set_owner('Example Community')
        ro.set_owner_allowed(True)
        ro.set_resource_pagination(False)
        ro.set_request_uri('/v2/groups/documents/{0}/upload'.format(document_id))

        #
        # retrieve and display the results
        #
        results = tc.api_request(ro)
        print('Status Code: {0}'.format(results.status_code))
