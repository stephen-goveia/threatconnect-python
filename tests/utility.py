#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Provide generic functions for use throughout the tests."""

import json
import os

from mock import patch


def start():
    patcher = patch('threatconnect.ThreatConnect.api_request', fake_api_request)
    patcher.start()


def fake_api_request(self, ro):
    resource_file = os.path.normpath('resources{0}.{1}'.format(ro._request_uri, ro._http_method))

    class ApiResponse:
        def __init__(self):
            self.status_code = 200
            self.headers = {'content-type': 'application/json'}

        def json(self):
            return json.load(open(resource_file, 'rb'))

        def close(self):
            return

    return ApiResponse()
