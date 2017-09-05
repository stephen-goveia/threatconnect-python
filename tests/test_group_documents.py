#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Test Document functions."""

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


def test_specific_document_retrieval(tc):
    """Retrieve the document with a specific id."""
    documents = tc.documents()
    filter = documents.add_filter()
    filter.add_id(390)
    documents.retrieve()
    assert(len(documents) == 1)


def test_attribute_retrieval(tc):
    """Retrieve a document's attributes."""
    documents = tc.documents()
    filter = documents.add_filter()
    filter.add_id(390)
    documents.retrieve()

    for document in documents:
        document.load_attributes()
        assert(len(document.attributes) == 2)


def test_create(tc):
    """Create a document."""
    documents = tc.documents()
    document = documents.add('file')
    document.set_file_name('file.zip')
    document.set_file_size(10)
    document.commit()
    assert document.id == 392


def test_upload(tc):
    """Upload content to a document."""
    documents = tc.documents()
    filter = documents.add_filter()
    filter.add_id(390)
    documents.retrieve()

    content = 'foobar'
    for document in documents:
        document.upload(content)
        document.commit()
        assert document.contents == content
