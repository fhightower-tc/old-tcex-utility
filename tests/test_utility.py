#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import pytest

from democritus import utility


@pytest.mark.noAPI
def test_is_group():
    group_types = ['adversary', 'campaign', 'document', 'email', 'incident', 'signature', 'threat']
    for group_type in group_types:
        assert utility.is_group(group_type)
        assert not utility.is_indicator(group_type)


@pytest.mark.noAPI
def test_is_indicator():
    indicator_types = ['address', 'emailaddress', 'file', 'host', 'url']
    for indicator_type in indicator_types:
        assert utility.is_indicator(indicator_type)
        assert not utility.is_group(indicator_type)


@pytest.mark.noAPI
def test_standardize_item_type():
    example_indicator_type = ['address', 'Address']
    for indicator_type in example_indicator_type:
        assert utility.standardize_item_type(indicator_type) == 'address'

    example_group_type = ['incident', 'Incident']
    for group_type in example_group_type:
        assert utility.standardize_item_type(group_type) == 'incident'


@pytest.mark.noAPI
def test_get_indicator_id_keys():
    assert utility._get_indicator_id_keys('address') == ['ip']


@pytest.mark.noAPI
def test_get_indicator_id_key():
    assert utility.get_indicator_id_key({
        'ip': '1.2.3.4',
        'type': 'Address'
    }) == 'ip'

    assert utility.get_indicator_id_key({
        'md5': 'a'*32,
        'sha1': 'b'*40,
        'sha256': 'c'*64,
        'type': 'file'
    }) == 'md5'


@pytest.mark.noAPI
def test_get_type_from_weblink():
    weblink = 'https://app.threatconnect.com/auth/indicators/details/address.xhtml?address=1.2.3.4'
    assert utility.get_type_from_weblink(weblink) == 'address'

    weblink = 'https://app.threatconnect.com/auth/indicators/details/host.xhtml?host=example.com&owners=1,2,3,4'
    assert utility.get_type_from_weblink(weblink) == 'host'

    weblink = 'https://app.threatconnect.com/auth/email/email.xhtml?email=123456&owner=Common%20Community'
    assert utility.get_type_from_weblink(weblink) == 'email'

    weblink = 'https://app.threatconnect.com/auth/email/email.xhtml?email=123456'
    assert utility.get_type_from_weblink(weblink) == 'email'

    weblink = 'https://app.threatconnect.com/auth/incident/incident.xhtml?incident=1293174306&owners=10666&owner=Technical%20Blogs%20and%20Reports'
    assert utility.get_type_from_weblink(weblink) == 'incident'

    weblink = 'https://app.threatconnect.com/auth/incident/incident.xhtml?incident=1293174306&owners=10666'
    assert utility.get_type_from_weblink(weblink) == 'incident'
