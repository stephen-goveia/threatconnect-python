#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Test Owner functions."""

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


def test_owner_retrieval(tc):
    """Retrieve all owners."""
    owners = tc.owners()
    owners.retrieve()

    assert len(owners) == 4


def test_general_owner_metrics_retrieval(tc):
    """Retrieve metrics for all owners."""
    owners = tc.owners()

    owners.retrieve_metrics()


# TODO: Is it possible to get metrics for a specific owner? (3)
# def test_specific_owner_metrics_retrieval(tc):
#     """."""
#     owners = tc.owners()

#     filter1 = owners.add_filter()
#     filter1.add_id(0)

#     owners.retrieve()

#     owners[0].retrieve_metrics()
