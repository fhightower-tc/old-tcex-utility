#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from democritus.elements import Elements

OWNER = 'Research Labs'

output_json = {
    'groups': [
    {
        'name': 'Test threat',
        'type': 'Threat',
        'tag': [
        {
            'name': 'Test'
        }],
        'attribute': [
        {
            'type': 'Description',
            'value': 'Test description'
        }]
    }],
    'indicators': [
    {
        'id': 'c4b51446-7956-11e8-82ac-60f81da82336',
        'external_id': None,
        'description': None,
        'source': None,
        'seclabels': [],
        'associations': [],
        'export': None,
        'summary': 'good.com',
        'type': 'Host',
        'rating': 0,
        'confidence': 0,
        'dns': False,
        'whois': False,
        'tag': [
        {
            'name': 'Test'
        }],
        'attribute': [
        {
            'type': 'Description',
            'value': 'Test description'
        }]
    },
    {
        'id': 'c4b517f0-7956-11e8-ad4f-60f81da82336',
        'external_id': None,
        'description': None,
        'source': None,
        'seclabels': [],
        'associations': [],
        'export': None,
        'summary': 'bad.com',
        'type': 'Host',
        'rating': 0,
        'confidence': 0,
        'dns': False,
        'whois': False,
        'tag': [
        {
            'name': 'Test'
        }],
        'attribute': [
        {
            'type': 'Description',
            'value': 'Test description'
        }]
    },
    {
        'id': 'c4b51ac0-7956-11e8-b84d-60f81da82336',
        'external_id': None,
        'description': None,
        'source': None,
        'seclabels': [],
        'associations': [],
        'export': None,
        'summary': 'ugly.com',
        'type': 'Host',
        'rating': 0,
        'confidence': 0,
        'dns': False,
        'whois': False,
        'tag': [
        {
            'name': 'Test'
        }],
        'attribute': [
        {
            'type': 'Description',
            'value': 'Test description'
        }]
    }],
    'file_occurrences': [],
    'group_to_indicator_associations': [],
    'group_to_group_associations': [],
    'indicator_to_indicator_associations': []
}

def test_create_from_tcex_json():
    e = Elements(OWNER)
    e.create_from_tcex_json(output_json)

    hosts = [host['hostName'] for host in e.get_items('Host')]
    assert 'good.com' in hosts
    assert 'bad.com' in hosts
    assert 'ugly.com' in hosts

    threats = [threat['name'] for threat in e.get_items('Threat')]
    assert 'Test threat' in threats


def test_create_from_tcex_json():
    e = Elements(OWNER)
    new_address = e.create_test_indicator('Address')
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