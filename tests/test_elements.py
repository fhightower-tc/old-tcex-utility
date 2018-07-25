#!/usr/bin/env python
# -*- coding: utf-8 -*-

import time

from democritus.elements import Elements

OWNER = 'Research Labs'


def test_create_group_from_tcex_json():
    e = Elements(OWNER)
    data = {
      "attribute": [
        {
          "type": "Description",
          "value": "Test Description"
        }
      ],
      "name": "Robin Sparkles",
      "tag": [
        {
          "name": "APT"
        },{
          "name": "CrimeWare"
        }
      ],
      "type": "Adversary"
    }
    e.create_group_from_tcex_json(data)
    e.process()


def _create_indicator():
    e = Elements(OWNER)
    e.add_default_metadata('File', {
        'attributes': [{
        'type': 'Description',
        'value': 'Test'
        }, {
        'type': 'Source',
        'value': 'Test'
        }]
    })
    e.create_indicator('File', 'D69AA87FC248F7FAAF5C3BD0B1B1359C')
    e.tcex.jobs.file_occurrence({
        "date" : "2014-11-03T00:00:00-05:00",
        "fileName" : "win999301.dll",
        "hash": "D69AA87FC248F7FAAF5C3BD0B1B1359C",
        "path" : "C:\\Windows\\System"
    })
    e.process()


def test_deduplication_1():
    _create_indicator()
    time.sleep(1)
    _create_indicator()

    e = Elements(OWNER)
    ind_json = e.get_item('File', 'D69AA87FC248F7FAAF5C3BD0B1B1359C', include_attributes=True, include_file_occurrences=True)
    assert len(ind_json['attribute']) == 2
    assert len(ind_json['fileOccurrences']) == 1


def test_attribute_deduplication():
    old_attributes = [{
        'type': 'Description',
        'value': '1'
    }, {
        'type': 'Description',
        'value': '2'
    }]
    new_attributes = [{
        'type': 'Description',
        'value': '1'
    }, {
        'type': 'Description',
        'value': '3'
    }]
    e = Elements()
    deduplicated_attributes = e._deduplicate_attributes(old_attributes, new_attributes)
    assert len(deduplicated_attributes) == 1

    old_attributes = [{
        'type': 'Description',
        'value': '1'
    }]
    new_attributes = [{
        'type': 'Source',
        'value': '1'
    }]
    e = Elements()
    deduplicated_attributes = e._deduplicate_attributes(old_attributes, new_attributes)
    assert len(deduplicated_attributes) == 1

    old_attributes = [{
        'type': 'Description',
        'value': '1'
    }]
    new_attributes = [{
        'type': 'Description',
        'value': '1'
    }]
    e = Elements()
    deduplicated_attributes = e._deduplicate_attributes(old_attributes, new_attributes)
    assert len(deduplicated_attributes) == 0


def test_file_occurrence_deduplication():
    old_file_occurrences = [{
        'fileName': 'a',
        'path': 'b',
        'date': 'c'
    }, {
        'fileName': 'a',
        'path': 'b',
        'date': 'd'
    }]
    new_file_occurrences = [{
        'fileName': 'a',
        'path': 'b',
        'date': 'c',
        'hash': 'hashValue'
    }, {
        'fileName': 'aa',
        'path': 'b',
        'date': 'c',
        'hash': 'hashValue'
    }]
    e = Elements()
    deduplicated_file_occurrences = e._deduplicate_file_occurrences(old_file_occurrences, new_file_occurrences, 'hashValue : hashValue2 : hashValue3')
    assert len(deduplicated_file_occurrences) == 1

    old_file_occurrences = [{
        'fileName': 'a',
        'path': 'b',
        'date': 'c'
    }]
    new_file_occurrences = [{
        'fileName': 'aa',
        'path': 'b',
        'date': 'c',
        'hash': 'hashValue'
    }]
    e = Elements()
    deduplicated_file_occurrences = e._deduplicate_file_occurrences(old_file_occurrences, new_file_occurrences, 'hashValue : hashValue2 : hashValue3')
    assert len(deduplicated_file_occurrences) == 1

    old_file_occurrences = [{
        'fileName': 'a',
        'path': 'b',
        'date': 'c'
    }]
    new_file_occurrences = [{
        'fileName': 'a',
        'path': 'b',
        'date': 'c',
        'hash': 'hashValue'
    }]
    e = Elements()
    deduplicated_file_occurrences = e._deduplicate_file_occurrences(old_file_occurrences, new_file_occurrences, 'hashValue : hashValue2 : hashValue3')
    assert len(deduplicated_file_occurrences) == 0
