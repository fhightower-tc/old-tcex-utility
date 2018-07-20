#!/usr/bin/env python
# -*- coding: utf-8 -*-

from democritus.elements import Elements
from democritus.molecules import Molecules

OWNER = 'Research Labs'


def test_add_attributes_to_items_by_sec_label():
    m = Molecules(OWNER)
    m.add_attributes_to_items_by_sec_label([{
        "type": "Description",
        "value": "Test"
    }], 'TLP Red', 'address')
    # TODO: add some validation here


def test_get_items_by_attribute():
    m = Molecules(OWNER)
    items = m.get_items_by_attribute({
        "type": "Description",
        "value": "Test"
    }, 'address')
    assert len(items) > 0


def test_get_items_by_sec_label():
    m = Molecules(OWNER)
    items = m.get_items_by_sec_label('TLP Red', 'address')
    assert len(items) > 0


def test_get_items_by_tag():
    m = Molecules(OWNER)
    items = m.get_items_by_tag('Test', 'address')
    assert len(items) > 0


def test_get_all_indicators_by_tag():
    m = Molecules(OWNER)
    addresses = m.get_items_by_tag('Test', 'address')
    indicators = m.get_items_by_tag('Test', 'indicators')
    assert len(indicators) > len(addresses)


def test_get_all_groups_by_tag():
    m = Molecules(OWNER)
    incidents = m.get_items_by_tag('Test', 'incident')
    groups = m.get_items_by_tag('Test', 'groups')
    assert len(groups) > len(incidents)


def test_replace_tag_on_one_type():
    m = Molecules(OWNER)
    old_tag = 'Test'
    new_tags = ['New Tag']

    addresses = m.get_items_by_tag(old_tag, 'address')
    original_length = len(addresses)
    assert original_length > 0

    m.replace_tag(old_tag, new_tags, 'address')

    addresses = m.get_items_by_tag(old_tag, 'address')
    assert len(addresses) == 0
    addresses = m.get_items_by_tag(new_tags[0], 'address')
    assert len(addresses) == original_length

    m.replace_tag(new_tags[0], [old_tag], 'address')


def test_replace_tag():
    m = Molecules(OWNER)
    old_tag = 'Test'
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
