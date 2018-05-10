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
