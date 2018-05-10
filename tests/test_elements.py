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
