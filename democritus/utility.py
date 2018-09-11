#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import inflect
import re

INDICATOR_BASE_TEMPLATES = {
    'address': '1.2.{}.{}',
    'emailaddress': '{}@example.com',
    'file': '{}',
    'host': '{}.com',
    'url': 'https://{}.com/'
}

ITEM_TYPE_TO_API_BRANCH = {
    'address': 'indicators/addresses',
    # there are two entries for cidr ranges to handle the various nomenclatures used to describe cidr ranges from different packages
    'cidr': 'indicators/cidrBlocks',
    'cidrBlock': 'indicators/cidrBlocks',
    'userAgent': 'indicators/userAgents',
    'useragent': 'indicators/userAgents',
    'emailaddress': 'indicators/emailAddresses',
    'emailAddress': 'indicators/emailAddresses',
    'file': 'indicators/files',
    'host': 'indicators/hosts',
    'url': 'indicators/urls',
    'adversary': 'groups/adversaries',
    'campaign': 'groups/campaigns',
    'document': 'groups/documents',
    'email': 'groups/emails',
    'incident': 'groups/incidents',
    'signature': 'groups/signatures',
    'threat': 'groups/threats',
    'victim': 'victims'
}

INDICATOR_WEBLINK_CLASSIFIER = {
    '?address=': 'Address',
    '?emailaddress=': 'EmailAddress',
    '?file=': 'File',
    '?host=': 'Host',
    'url.xhtml': 'Url'
}

INDICATOR_TYPE_TO_ID_KEY = {
    'address': 'ip',
    'cidrblock': 'cidrBlock',
    'emailaddress': 'address',
    'file': ['md5', 'sha1', 'sha256'],
    'host': 'hostName',
    'url': 'text',
    # this is necessary to handle both the name of the entity returned from the API and the key of the actual indicator value (which is 'User Agent String')
    'useragent': ['userAgent', 'User Agent String'],
}

GROUP_ABBREVIATIONS = {
    'adv': 'adversary',
    'cam': 'campaign',
    'doc': 'document',
    'ema': 'email',
    'inc': 'incident',
    'sig': 'signature',
    'thr': 'threat'
}

INDICATOR_ABBREVIATIONS = {
    'add': 'address',
    'emadd': 'emailAddress',
    'file': 'file',
    'host': 'host',
    'url': 'url'
}


def is_group(item_type):
    """Return whether or not the given item is a group or not."""
    item_type = standardize_item_type(item_type)
    return item_type in GROUP_ABBREVIATIONS.values()


def is_indicator(item_type):
    """Return whether or not the given item is an indicator or not."""
    item_type = standardize_item_type(item_type)
    return item_type in INDICATOR_ABBREVIATIONS.values()


def standardize_item_type(item_type):
    item_type = item_type.replace(' ', '')
    return inflect.engine().singular_noun(ITEM_TYPE_TO_API_BRANCH[item_type.lower()].split('/')[-1])


def _get_indicator_id_keys(indicator_type):
    """Return the keys which provide the indicator's id for the given indicator type."""
    if isinstance(INDICATOR_TYPE_TO_ID_KEY[standardize_item_type(indicator_type).lower()], list):
        return INDICATOR_TYPE_TO_ID_KEY[standardize_item_type(indicator_type).lower()]
    else:
        return [INDICATOR_TYPE_TO_ID_KEY[standardize_item_type(indicator_type).lower()]]


def get_indicator_id_key(indicator_json):
    """Return the key which provides the indicator's id for the given indicator type."""
    item_id_key = None
    item_id_keys = _get_indicator_id_keys(indicator_json['type'])
    for key in item_id_keys:
        if indicator_json.get(key):
            item_id_key = key
            break
    return item_id_key


def get_api_base_from_type(item_type):
    """Return the base API path for the given type."""
    return ITEM_TYPE_TO_API_BRANCH[standardize_item_type(item_type)]


# TODO: can this function and all references to it be removed?
def get_type_from_weblink(weblink):
    """Get the item's type from a weblink."""
    pattern = '\/([a-z]*)\.xhtml'
    matches = re.findall(pattern, weblink.lower())
    return matches[0]


# TODO: split this function up to only do one thing (return the base API path). The key which provides the item's id can be found using the `get_indicator_id_key` function
def get_api_details(item):
    """Return the base API path and the key which provides the item's id."""
    item_api_base = str()
    item_id_key = str()

    if is_group(item['type']):
        item_api_base = get_api_base_from_type(item['type'])
        item_id_key = 'id'
    elif is_indicator(item['type']):
        item_api_base = get_api_base_from_type(item['type'])
        item_id_key = get_indicator_id_key(item)
    elif standardize_item_type(item['type']) == 'victim':
        item_api_base = get_api_base_from_type(item['type'])
        item_id_key = 'id'
    else:
        print('Unable to identify the type "{}"'.format(item['type']))

    return item_api_base, item_id_key
