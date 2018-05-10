#!/usr/bin/env python
# -*- coding: utf-8 -*-

from tcex_utility.tcex_elements import Elements
from tcex_utility.tcex_molecules import Molecules

OWNER = 'Research Labs'


def test_get_security_labels():
    e = Elements(OWNER)
    indicators_with_sec_label = e.get_items_by_sec_label('TLP Red', 'Address')
    assert len(indicators_with_sec_label) > 0
