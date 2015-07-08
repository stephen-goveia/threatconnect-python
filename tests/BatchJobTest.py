import unittest
from TestUtilities import *


class BatchJobTest(unittest.TestCase):

    def setUp(self):
        testSetup(self)

    def tearDown(self):
        testTeardown(self)

    def test_filter_by_id(self):
        batchJobs = self.threatconnect.batchJobs()
        filter = batchJobs.add_filter()
        filter.add_id(32)
        batchJobs.retrieve()

        assert(len(batchJobs) == 1)

    def test_create_batchjob(self):
        batchJobs = self.threatconnect.batchJobs()
        batchJob = batchJobs.add()
        batchJob.set_haltOnError(False)
        batchJob.set_attributeWriteType('Replace')
        batchJob.set_action('Create')

        batchJob.commit()

    def test_upload(self):
        batchJobs = self.threatconnect.batchJobs()
        batchJob = batchJobs.update(32)
        batchJob.upload('test upload')

        batchJob.commit()




