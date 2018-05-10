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
    }], 'Address', 'TLP Red')


def test_get_items_by_attribute():
    m = Molecules(OWNER)
    items = m.get_items_by_attribute({
        "type": "Description",
        "value": "Test"
    }, 'Address')
    assert len(items) > 0


def test_get_items_by_sec_label():
    m = Molecules(OWNER)
    items = m.get_items_by_sec_label('TLP Red', 'Address')
    assert len(items) > 0


def test_get_items_by_tag():
    m = Molecules(OWNER)
    items = m.get_items_by_tag('Test', 'Address')
    assert len(items) > 0


def test_update_attributes_on_items():
    pass
    # TODO: implement
