#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Test Indicator functions."""

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


def test_indicator_retrieval(tc):
    """Retrieve all indicators."""
    indicators = tc.indicators()
    indicators.retrieve()

    assert(len(indicators) == 91)


def test_specific_indicator_retrieval(tc):
    """Retrieve a specific indicator by filtering based on indicator."""
    indicators = tc.indicators()
    filter = indicators.add_filter()
    filter.add_indicator('422AD421127685E3EF4A44B546258107')
    indicators.retrieve()

    assert(len(indicators) == 1)


def test_add_attribute(tc):
    """Add an attribute."""
    indicators = tc.indicators()
    filter = indicators.add_filter()
    filter.add_indicator('www.google.com')
    indicators.retrieve()

    for indicator in indicators:
        indicator.add_attribute('Description', 'foobar')
        assert len(indicator.attributes) == 1
