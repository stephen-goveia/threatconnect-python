import os.path
import unittest
import json

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


class IndicatorTests(unittest.TestCase):

    def setUp(self):
        self.patcher = patch('threatconnect.ThreatConnect.api_request', fake_api_request)
        self.patcher.start()
        self.threatconnect = ThreatConnect('accessId', 'secretKey', 'System', '//')

    def tearDown(self):
        self.patcher.stop()

    def test_retrieve(self):
        indicators = self.threatconnect.indicators()
        indicators.retrieve()

        assert(len(indicators) == 91)

    def test_filter_by_indicator(self):
        indicators = self.threatconnect.indicators()
        filter = indicators.add_filter()
        filter.add_indicator('422AD421127685E3EF4A44B546258107')
        indicators.retrieve()

        assert(len(indicators) == 1)