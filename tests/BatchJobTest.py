import unittest
from TestUtilities import *


class BatchJobTest(unittest.TestCase):

    def setUp(self):
        test_setup(self)

    def tearDown(self):
        test_teardown(self)

    def test_filter_by_id(self):
        batch_jobs = self.threatconnect.batch_jobs()
        filter = batch_jobs.add_filter()
        filter.add_id(32)
        batch_jobs.retrieve()

        assert(len(batch_jobs) == 1)

    def test_create_batch_job(self):
        batch_jobs = self.threatconnect.batch_jobs()
        batch_job = batch_jobs.add()
        batch_job.set_halt_on_error(False)
        batch_job.set_attribute_write_type('Replace')
        batch_job.set_action('Create')
        batch_job.set_owner('System')

        batch_job.commit()

    def test_upload(self):
        batch_jobs = self.threatconnect.batch_jobs()
        batch_job = batch_jobs.update(32)
        batch_job.upload('test upload')

        batch_job.commit()