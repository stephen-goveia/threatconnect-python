import unittest
from TestUtilities import *


class DocumentTests(unittest.TestCase):

    def setUp(self):
        test_setup(self)

    def tearDown(self):
        test_teardown(self)

    def test_filter_by_id(self):
        documents = self.threatconnect.documents()
        filter = documents.add_filter()
        filter.add_id(390)
        documents.retrieve()
        assert(len(documents) == 1)

        for document in documents:
            document.load_attributes()
            assert(len(document.attributes) == 2)

    def test_upload_document(self):
        documents = self.threatconnect.documents()
        filter = documents.add_filter()
        filter.add_id(390)
        documents.retrieve()
        assert(len(documents) == 1)
        content = 'foobar'
        for document in documents:
            document.upload(content)
            document.commit()
            assert document.contents == content

    def test_create(self):
        documents = self.threatconnect.documents()
        document = documents.add('file')
        document.set_file_name('file.zip')
        document.set_file_size(10)
        document.commit()
        assert document.id == 392

