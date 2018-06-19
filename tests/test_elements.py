#!/usr/bin/env python
# -*- coding: utf-8 -*-

from tcex_utility.tcex_elements import Elements

OWNER = 'Research Labs'


def test_delete_tag():
    e = Elements(OWNER)
    e.delete_tag({
        'webLink': '/address.xhtml',
        'ip': '1.2.3.4'
    }, 'Test')


def test_create_from_tcex_json():
    e = Elements(OWNER)
    new_address = e._generate_test_indicator('Address')
    tcex_json = {
        'groups': [],
        'indicators': [{
            "summary": new_address,
            "type": "Address",
        }],
        'file_occurrences': [],
        'group_to_group_associations': [],
        'group_to_indicator_associations': [],
        'indicator_to_indicator_associations': []
    }
    e.create_from_tcex_json(tcex_json)
    assert new_address in [entry['ip'] for entry in e.get_items('Address')]

    # TODO: Build out some more tests that test the associations, file occurrences, and groups
