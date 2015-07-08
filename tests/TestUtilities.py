import json
import os
from threatconnect import *
from mock import patch


def fake_api_request(self, ro):
    resource_file = os.path.normpath('resources{0}.{1}'.format(ro._request_uri, ro._http_method))

    class Api_Response:
        def __init__(self):
            self.status_code = 200
            self.headers = {'content-type': 'application/json'}

        def json(self):
            return json.load(open(resource_file, 'rb'))

        def close(self):
            return

    return Api_Response()

def testSetup(self):
    self.patcher = patch('threatconnect.ThreatConnect.api_request', fake_api_request)
    self.patcher.start()
    self.threatconnect = ThreatConnect('accessId', 'secretKey', 'System', '//')

def testTeardown(self):
    self.patcher.stop()
