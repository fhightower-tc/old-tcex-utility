#!/usr/bin/env python
# -*- coding: utf-8 -*-

from tcex_utility.tcex_elements import Elements
from tcex_utility.tcex_molecules import Molecules

OWNER = 'Research Labs'


def test_add_attributes_to_items_by_sec_label():
    m = Molecules(OWNER)
    m.add_attributes_to_items_by_sec_label([{
        "type": "Description",
        "value": "Test"
    }], 'TLP Red', 'address')


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


def test_update_attributes_on_items():
    pass
    # TODO: implement
