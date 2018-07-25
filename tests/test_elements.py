#!/usr/bin/env python
# -*- coding: utf-8 -*-

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


def test_deduplication():
    _create_indicator()
    _create_indicator()

    e = Elements(OWNER)
    ind_json = e.get_item('File', 'D69AA87FC248F7FAAF5C3BD0B1B1359C', include_attributes=True, include_file_occurrences=True)
    assert len(ind_json['attribute']) == 2
    assert len(ind_json['fileOccurrences']) == 1

