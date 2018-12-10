#!/usr/bin/env python
# -*- coding: utf-8 -*-

import time

from democritus.elements import Elements
from democritus.molecules import Molecules

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


def test_file_attribute_deduplication():
    e = Elements(OWNER)
    file_summary = '{} : {} : {}'.format('a'*32, 'b'*40, 'c'*64)
    indicator_data = {
        'indicators': [{
            'summary': file_summary,
            'attribute': [{
                'type': 'Description',
                'value': 'Test'
            }, {
                'type': 'Source',
                'value': 'Test'
            }],
            'type': 'File'
        }]
    }

    e.create_from_tcex_json(indicator_data)
    e.create_from_tcex_json(indicator_data)

    ind_json = e.get_item('File', 'a'*32, include_attributes=True, include_file_occurrences=True)
    assert len(ind_json['attribute']) == 2


def test_type():
    """Make sure the json returned for a specific item includes the type of the item."""
    _create_indicator()
    e = Elements(OWNER)
    items = e.get_items_by_type('Address', include_attributes=True, include_tags=True)
    for item in items:
        assert item.get('type')


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


def test_log_processing_invalid_indicator():
    e = Elements(owner=OWNER, process_logs=True)
    e.create_indicator('URL', 'https://HIGHTOWER.space')
    errors = e.process()
    assert len(errors['exclusion_list_failure']) == 0
    assert len(errors['invalid_indicator']) == 1
    assert ' - tcex - ERROR - Failed adding indicator https://HIGHTOWER.space type URL ({"status":"Failure","message":"Please enter a valid Url"}).' in errors['invalid_indicator'][0]


def test_log_processing_excluded_indicator():
    e = Elements(owner=OWNER, process_logs=True)
    e.create_indicator('URL', 'https://google.com')
    errors = e.process()
    assert len(errors['exclusion_list_failure']) >= 1
    assert len(errors['invalid_indicator']) == 0
    assert 'Failed adding indicator https://google.com type URL ({"status":"Failure","message":"This indicator is contained on a system-wide exclusion list."}).' in errors['exclusion_list_failure'][0]


def test_logging():
    e = Elements(owner=OWNER, process_logs=True)
    e.create_indicator('URL', 'https://HIGHTOWER.space')
    e.process()
    # read the log file to make sure errors where logged
    with open(e.tcex.log.handlers[-1].baseFilename, 'r') as f:
        text = f.read()
        assert 'Failed adding indicator https://HIGHTOWER.space type URL' in text


# TODO: the test below is not working yet b/c the ability to retrieve associations when using `get_items_by_type` has not been implemented yet
def test_get_associations():
    m = Molecules(owner=OWNER)
    m.create_from_symbolic_pattern('inc-file', 2)
    m.process()

    incidents = m.get_items_by_type('incidents', include_associations=True)
    assert len(incidents[-1]['associations']) == 1
    assert len(incidents[-2]['associations']) == 1


def test_group_deduplication():
    """Make sure groups are being deduplicated based on group name."""
    e = Elements(owner=OWNER)
    e.create_group('Threat', 'Test threat')
    e.process()
    original_threat_count = len(e.get_items_by_type('threat'))

    # try to create an threat with the same name and make sure it is not created
    e.create_group('Threat', 'Test threat')
    e.process(dont_create_duplicate_groups=True)
    new_threat_count = len(e.get_items_by_type('threat'))
    assert new_threat_count == original_threat_count


def test_indicator_deletion():
    e = Elements(owner=OWNER)
    e.create_indicator('Address', '5.4.33.2')
    e.process()
    assert len(e.get_item('Address', '5.4.33.2')) > 0
    print("e.get_item('Address', '5.4.33.2') {}".format(e.get_item('Address', '5.4.33.2')))
    e.delete_indicator('Address', '5.4.33.2')
    assert len(e.get_item('Address', '5.4.33.2')) == 0


def test_attribute_deduplication_cidr():
    # this function assumes there is a cidr range indicator ('1.2.3.4/20') with a description attribute with a value of 'Test'
    e = Elements(owner=OWNER)
    e.create_from_tcex_json({
        'indicators': [{
          "attribute": [
            {
              "type": "Description",
              "value": "Test"
            }
          ],
          "confidence": 5,
          "rating": "3",
          "summary": "1.2.3.4/20",
          "type": "CIDR"
        }]
    })
    e.process()

    e = Elements(OWNER)
    ind_json = e.get_item('CIDR', '1.2.3.4/20', include_attributes=True, include_file_occurrences=True)
    print("ind_json {}".format(ind_json))
    assert len(ind_json['attribute']) == 1
