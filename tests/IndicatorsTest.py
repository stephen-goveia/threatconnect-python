import unittest
from TestUtilities import *


class IndicatorTests(unittest.TestCase):

    def setUp(self):
        testSetup(self)

    def tearDown(self):
        testTeardown(self)

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