import unittest
from TestUtilities import *


class IndicatorTests(unittest.TestCase):

    def setUp(self):
        test_setup(self)

    def tearDown(self):
        test_teardown(self)

    def test_retrieve(self):
        indicators = self.threatconnect.indicators()
        indicators.retrieve()

        assert(len(indicators) == 91)

    def test_filter_by_indicator(self):
        indicators = self.threatconnect.indicators()
        filter = indicators.add_filter()
        # file
        filter.add_indicator('422AD421127685E3EF4A44B546258107')
        indicators.retrieve()

        assert(len(indicators) == 1)

    def test_add_attribute(self):
        indicators = self.threatconnect.indicators()
        filter = indicators.add_filter()
        filter.add_indicator('www.google.com')
        indicators.retrieve()

        for indicator in indicators:
            indicator.add_attribute('Description', 'foobar')
            assert len(indicator.attributes) == 1