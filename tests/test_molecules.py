#!/usr/bin/env python
# -*- coding: utf-8 -*-

from democritus.elements import Elements
from democritus.molecules import Molecules

OWNER = 'Research Labs'


def _create_group(molecule):
    molecule.add_default_metadata('Threat', {
        'attributes': [{
            'type': 'Description',
            'value': 'Test'
        }],
        'tags': [{
            'name': 'Test Tag'
        }]
    })
    molecule.create_group('Threat', 'Test Threat')
    molecule.process()


def _create_indicator(molecule):
    molecule.add_default_metadata('File', {
        'attributes': [{
            'type': 'Description',
            'value': 'Test'
        }],
        'tags': [{
            'name': 'Test Tag'
        }]
    })
    molecule.create_indicator('File', 'D69AA87FC248F7FAAF5C3BD0B1B1359C')
    molecule.process()


def test_add_attributes_to_items_by_sec_label():
    m = Molecules(OWNER)
    m.add_attributes_to_items_by_sec_label([{
        "type": "Description",
        "value": "Test"
    }], 'TLP Red', 'File')
    # TODO: add some validation here


def test_get_items_by_attribute():
    m = Molecules(OWNER)
    _create_indicator(m)
    items = m.get_items_by_attribute({
        "type": "Description",
        "value": "Test"
    }, 'File')
    assert len(items) > 0


def test_get_items_by_sec_label():
    m = Molecules(OWNER)
    _create_indicator(m)
    items = m.get_items_by_sec_label('TLP Red', 'File')
    assert len(items) > 0


def test_get_items_by_tag():
    m = Molecules(OWNER)
    _create_indicator(m)
    items = m.get_items_by_tag('Test Tag', 'File')
    assert len(items) > 0


def test_get_all_indicators_by_tag():
    m = Molecules(OWNER)
    indicators = m.get_items_by_tag('Test Tag', 'indicators')
    assert len(indicators) > 0
    # this is just a test to make sure that both 'indicators' (all lower-cased) and 'Indicators' (title-cased) work
    indicators = m.get_items_by_tag('Test Tag', 'Indicators')
    assert len(indicators) > 0


def test_get_all_groups_by_tag():
    m = Molecules(OWNER)
    _create_group(m)
    groups = m.get_items_by_tag('Test Tag', 'groups')
    assert len(groups) > 0


def test_replace_tag_on_one_type():
    m = Molecules(OWNER)
    _create_indicator(m)
    old_tag = 'Test Tag'
    new_tags = ['New Tag']

    files = m.get_items_by_tag(old_tag, 'File')
    original_length = len(files)
    assert original_length > 0

    m.replace_tag(old_tag, new_tags, 'File')

    files = m.get_items_by_tag(old_tag, 'File')
    assert len(files) == 0
    files = m.get_items_by_tag(new_tags[0], 'File')
    assert len(files) == original_length

    m.replace_tag(new_tags[0], [old_tag], 'File')


def test_replace_tag():
    m = Molecules(OWNER)
    _create_indicator(m)
    old_tag = 'Test Tag'
    new_tags = ['New Tag']

    items = m.get_items_by_tag(old_tag)
    original_length = len(items)
    assert original_length > 0

    m.replace_tag(old_tag, new_tags)

    items = m.get_items_by_tag(old_tag)
    assert len(items) == 0
    items = m.get_items_by_tag(new_tags[0])
    assert len(items) == original_length

    # reset the tags
    m.replace_tag(new_tags[0], [old_tag])


def test_update_attributes_on_items():
    pass
    # TODO: implement


def test_export_group():
    m = Molecules(OWNER)
    group_json = m.export_group('Threat', 3143995)
    assert len(group_json) == 8
    assert group_json['name'] == 'Test threat'


def test_export_and_create():
    m = Molecules(OWNER)
    group_json = m.export_group('Threat', 3143995)
    assert len(group_json) == 8
    assert group_json['name'] == 'Test threat'
    group_json['name'] = 'New test threat'
    m.create_group_from_tcex_json(group_json)
    m.process()
