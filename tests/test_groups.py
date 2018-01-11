#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Test Group functions."""

import pytest
import threatconnect

import utility

# initialize mock
utility.start()


@pytest.fixture
def tc():
    """Initialize instance of TC SDK."""
    tc = threatconnect.ThreatConnect('accessId', 'secretKey', 'System', '//')
    return tc


def test_group_retrieval(tc):
    """Retrieve all groups."""
    groups = tc.groups()
    groups.retrieve()

    assert(len(groups) == 7)
