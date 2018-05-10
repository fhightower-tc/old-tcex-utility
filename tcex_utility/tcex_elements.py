#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Basic, elemental functions for TCEX."""

try:
    import ConfigParser
except:
    import configparser as ConfigParser
import hashlib
import json
import os
import random
import sys
import uuid

import inflect
from tcex import TcEx

INDICATOR_BASE_TEMPLATES = {
    'Address': '1.2.{}.{}',
    'EmailAddress': '{}@example.com',
    'File': '{}',
    'Host': '{}.com',
    'Url': 'https://{}.com/'
}

INDICATOR_WEBLINK_CLASSIFIER = {
    '?address=': 'Address',
    '?emailaddress=': 'EmailAddress',
    '?file=': 'File',
    '?host=': 'Host',
    'url.xhtml': 'Url',
}

INDICATOR_TYPE_TO_ID_KEY = {
    'Address': 'ip',
    'EmailAddress': 'address',
    'File': ['md5', 'sha1', 'sha256'],
    'Host': 'hostName',
    'Url': 'text'
}

API_VERSION = 'v2'


class Elements(object):
    def __init__(self, owner=None):
        self.owner = owner
        self.tcex = TcEx()
        self._authenticate()
        self.group_abbreviations = {
            'adv': 'Adversary',
            'cam': 'Campaign',
            'doc': 'Document',
            'ema': 'Email',
            'inc': 'Incident',
            'sig': 'Signature',
            'thr': 'Threat'
        }
        self.indicator_abbreviations = {
            'add': 'Address',
            'emadd': 'EmailAddress',
            'file': 'File',
            'host': 'Host',
            'url': 'Url'
        }
        self.default_metadata = {}
        self.inflect_engine = inflect.engine()

    def _authenticate(self):
        config = ConfigParser.RawConfigParser()
        config_file_path = os.path.abspath(os.path.join(os.path.dirname(__file__), './tc.conf'))
        config.read(config_file_path)

        try:
            api_access_id = config.get('threatconnect', 'api_access_id')
            api_secret_key = config.get('threatconnect', 'api_secret_key')
            api_default_org = config.get('threatconnect', 'api_default_org')
            api_base_url = config.get('threatconnect', 'api_base_url')
        except ConfigParser.NoOptionError:
            print('Could not read configuration file at {}'.format(config_file_path))
            sys.exit(1)
        except ConfigParser.NoSectionError:
            print("Unable to read config file at {}".format(config_file_path))
            raise

        self.tcex.args.api_access_id = api_access_id
        self.tcex.args.api_secret_key = api_secret_key
        self.tcex.args.tc_api_path = api_base_url.rstrip('/')
        if self.owner is None:
            self.owner = api_default_org

    def _check_for_default_metdata(self, object_data, object_type):
        """See if there is metadata for objects of the given type and if so, add it to the object's data."""
        if self.default_metadata.get(object_type):
            if self.default_metadata[object_type].get('attribute'):
                if object_data.get('attribute'):
                    object_data['attribute'].extend(self.default_metadata[object_type].get('attribute'))
                else:
                    object_data['attribute'] = self.default_metadata[object_type].get('attribute')
            if self.default_metadata[object_type].get('tag'):
                if object_data.get('tag'):
                    object_data['tag'].extend(self.default_metadata[object_type].get('tag'))
                else:
                    object_data['tag'] = self.default_metadata[object_type].get('tag')
            if self.default_metadata[object_type].get('eventDate'):
                object_data['eventDate'] = self.default_metadata[object_type].get('eventDate')
        return object_data

    def _create_group(self, group_type, group_name=''):
        # if no group name is given, create one with a uuid
        if group_name == '':
            group_name = 'Test {} {}'.format(group_type, str(uuid.uuid4()).split('-')[0])
        group_data = {
            'name': group_name,
            'type': group_type
        }
        if group_type == 'Document':
            group_data['fileData'] = 'Test document'
            group_data['fileName'] = 'test.txt'
        if group_type == 'Signature':
            group_data['fileName'] = 'test.yara'
            group_data['fileText'] = 'Test Signature'
            group_data['fileType'] = 'Yara'
        group_data = self._check_for_default_metdata(group_data, group_type)
        self.tcex.jobs.group(group_data)
        return group_data

    def _get_indicator_id_key(self, indicator_type):
        """Return the key which provides the indicator's id for the given indicator type."""
        if isinstance(INDICATOR_TYPE_TO_ID_KEY[indicator_type], list):
            return INDICATOR_TYPE_TO_ID_KEY[indicator_type]
        else:
            return [INDICATOR_TYPE_TO_ID_KEY[indicator_type]]

    def _get_api_base_from_type(self, base_type, item_type):
        """Return the base API path for the given type."""
        return '{}/{}'.format(base_type, self.inflect_engine.plural(item_type.lower()))

    def _get_api_details(self, item, item_type):
        """Return the base API path and the key which provides the item's id."""
        item_api_base = str()
        item_id_key = str()

        if self._identify_group(item_type):
            item_api_base = self._get_api_base_from_type('groups', item_type)
            item_id_keys = 'id'
        elif self._identify_indicator(item_type):
            item_api_base = self._get_api_base_from_type('indicators', item_type)
            item_id_keys = self._get_indicator_id_key(item_type)
            for key in item_id_keys:
                if item.get(key):
                    item_id_key = key
                    break
        else:
            print('Unable to identify the type {}'.format(item_type))

        return item_api_base, item_id_key

    def _generate_test_indicator(self, indicator_type):
        """Create a test indicator of the given type."""
        host_base = str(uuid.uuid4()).split('-')[0]
        base_indicator = INDICATOR_BASE_TEMPLATES[indicator_type]

        if indicator_type == 'Address':
            return base_indicator.format(random.randint(0, 255), random.randint(0, 255))
        elif indicator_type == 'EmailAddress':
            return base_indicator.format(host_base)
        elif indicator_type == 'File':
            return hashlib.md5(host_base.encode('utf-8')).hexdigest()
        elif indicator_type == 'Host':
            return base_indicator.format(host_base)
        elif indicator_type == 'Url':
            return base_indicator.format(host_base)

    def get_attributes(self, item, item_type):
        """Get all attributes for the given item."""
        item_api_base, item_id_key = self._get_api_details(item, item_type)
        api_path = '{}/{}/attributes'.format(item_api_base, item[item_id_key])
        results = self._api_request('GET', api_path)
        return results['attribute']

    def delete_attributes(self, item, item_type, attribute_id):
        """Get all attributes for the given item."""
        item_api_base, item_id_key = self._get_api_details(item, item_type)
        api_path = '{}/{}/attributes/{}'.format(item_api_base, item[item_id_key], attribute_id)
        results = self._api_request('DELETE', api_path)
        return results

    def get_items(self, item_type, includeAttributes=False, includeTags=False):
        """Get all items of the given type."""
        items = list()
        # if there is no reason to make an API call, just use the tcex.resource library
        if not includeAttributes and not includeTags:
            # TODO: singularize and title case the item_type so that 'address', 'Addresses', and 'Address' will all work
            item_data = self.tcex.resource(item_type)
            item_data.owner = self.owner
            # paginate over results
            for item in item_data:
                items.extend(item['data'])
            return items
        # if we want to get attributes and/or tags, make an API request
        else:
            item_api_base, item_id_key = self._get_api_details({}, item_type)
            results = self._api_request('GET', item_api_base, includeAttributes=includeAttributes, includeTags=includeTags)
            items = results.get(item_type.lower())
            return items

    def get_sec_labels(self, item, item_type):
        """Get security labels for the given item."""
        item_api_base, item_id_key = self._get_api_details(item, item_type)
        return self._api_request('GET', '{}/{}/securityLabels'.format(item_api_base, item[item_id_key]))

    def _create_indicator(self, indicator_type, indicator=''):
        if indicator == '':
            indicator = self._generate_test_indicator(indicator_type)
        indicator_data = {
            'summary': indicator,
            'type': indicator_type
        }
        indicator_data = self._check_for_default_metdata(indicator_data, indicator_type)
        self.tcex.jobs.indicator(indicator_data)
        # this is done to normalize the group and indicator data... it may be better to do this in another function
        indicator_data['name'] = indicator_data['summary']
        return indicator_data

    def _create_association(self, object1, object2, custom_association_name=''):
        """Create an association between the two objects."""
        if object1['type'] in self.group_abbreviations.values():
            # group to group association
            if object2['type'] in self.group_abbreviations.values():
                self.tcex.jobs.association({
                    "association_value": object1['name'],
                    "association_type": object1['type'],
                    "resource_value": object2['name'],
                    "resource_type": object2['type']
                })
            # group to indicator association
            else:
                self.tcex.jobs.group_association({
                    "group_name": object1['name'],
                    "group_type": object1['type'],
                    "indicator": object2['name'],
                    "indicator_type": object2['type']
                })
        else:
            # indicator to group association
            if object2['type'] in self.group_abbreviations.values():
                self.tcex.jobs.group_association({
                    "group_name": object2['name'],
                    "group_type": object2['type'],
                    "indicator": object1['name'],
                    "indicator_type": object1['type']
                })
            # indicator to indicator association
            else:
                # TODO: implement this feature so that custom indicator to indicator associations can be created
                self.tcex.jobs.association({
                    "association_value": object1['name'],
                    "association_type": tcex.safe_rt(object1['type']),
                    "resource_value": object2['name'],
                    "resource_type": tcex.safe_rt(object2['type']),
                    "custom_association_name": custom_association_name
                })
            # TODO: handle file occurrence associations

    def _api_request(self, method, api_path, body={}, includeAttributes=False, includeTags=False):
        """Make an api request."""
        r = self.tcex.request_tc()
        r.url = '{}/{}/{}'.format(self.tcex.args.tc_api_path, API_VERSION, api_path)
        r.add_header('Content-Type', 'application/json')
        r.add_payload('owner', self.owner)
        if includeAttributes:
            r.add_payload('includeAttributes', 'true')
        if includeTags:
            r.add_payload('includeTags', 'true')
        if method != 'GET':
            r.body = json.dumps(body)
        r.http_method = method
        response = r.send()

        if response.ok:
            if response.json().get('data'):
                return response.json()['data']
            else:
                return response.json()
        else:
            raise RuntimeError('{} response from API: {}'.format(response.status_code, response.text))

    def _get_iso_date_format(self, date):
        """Return the iso format (with a trailing 'Z') of the given date."""
        return self.tcex.utils.format_datetime(date, date_format='%Y-%m-%dT%H:%M:%S') + 'Z'

    def _set_event_date(self, event_date, incident_id):
        """Set the event date for the incident with the given id."""
        request_body = {
            'eventDate': self._get_iso_date_format(event_date)
        }
        self._api_request('PUT', 'groups/incidents/{}'.format(incident_id), request_body)

    def _identify_item_type(self, search_type, item_types):
        """Look for the search_type in the given item_types."""
        if search_type in item_types.keys() or search_type in item_types.values():
            return True
        else:
            return False

    def _identify_group(self, item_type):
        """See if the item_type is a group."""
        return self._identify_item_type(item_type, self.group_abbreviations)

    def _identify_indicator(self, item_type):
        """See if the item_type is an indicator."""
        return self._identify_item_type(item_type, self.indicator_abbreviations)

    def _add_attributes(self, item_api_base, item_id, attributes):
        """Add the attributes to the given item."""
        for attribute in attributes:
            self._api_request('POST', '{}/{}/attributes'.format(item_api_base, item_id), attribute)

    def _add_sec_labels(self, item_api_base, item_id, sec_labels):
        """Add the security labels to the given item."""
        for label in sec_labels:
            self._api_request('POST', '{}/{}/securityLabels/{}'.format(item_api_base, item_id, label))

    def _add_tags(self, item_api_base, item_id, tags):
        """Add the tags to the given item."""
        for tag in tags:
            self._api_request('POST', '{}/{}/tags/{}'.format(item_api_base, item_id, tag))

    def add_default_metadata(self, metadata, object_type):
        """Add metadata which will be added to all objects of the given type."""
        # TODO: add validation to make sure the object_type is valid
        self.default_metadata[object_type] = metadata

    def set_owner(self, owner_name):
        """Set the owner for TCEX."""
        self.owner = owner_name

    def create_multiple_groups(self, count=100, base_name='Test Group', group_type='Incident'):
        """Create the number of groups specified by the count."""
        for x in range(0, count):
            self._create_group(group_type, group_name=base_name + ' {}'.format(x))

    def create_from_symbolic_pattern(self, pattern, count=1):
        # TODO: move this function to the molecules file
        """Create groups represented symbolically."""
        associations = list()
        objects = list()
        for section in pattern.split("-"):
            associations.append("-")
            for i in range(0, section.count('=')):
                associations.append("=")
            objects.extend(section.split("="))

        # remove the first association which is erroneous
        associations = associations[1:]

        for x in range(0, count):
            # create objects
            created_objects = list()
            for obj in objects:
                if obj in self.group_abbreviations:
                    created_objects.append(self._create_group(self.group_abbreviations[obj]))
                elif obj in self.indicator_abbreviations:
                    created_objects.append(self._create_indicator(self.indicator_abbreviations[obj]))

            if len(associations) > 0:
                # create associations
                for i in range(0, len(created_objects) - 1):
                    self._create_association(created_objects[i], created_objects[i + 1])
                    if associations[i] == '=':
                        self._create_association(created_objects[i], created_objects[i + 2])

    def set_event_dates(self, event_date, incidents=None):
        """Set the event dates for the given incidents."""
        if incidents is None:
            incidents = self.get_groups('Incident')

        for incident in incidents:
            self._set_event_date(event_date, incident['id'])

    def add_attributes(self, attributes, items, item_type):
        """Add attributes to the given items."""
        for item in items:
            item_api_base, item_id_key = self._get_api_details(item, item_type)
            self._add_attributes(item_api_base, item[item_id_key], attributes)

    # TODO: consolidate add_attributes, add_sec_labels, and add_tags functions
    def add_sec_labels(self, sec_labels, items, item_type):
        """Add security labels to the given items."""
        for item in items:
            item_api_base, item_id_key = self._get_api_details(item, item_type)
            self._add_sec_labels(item_api_base, item[item_id_key], sec_labels)

    def add_tags(self, tags, items, item_type):
        """Add tags to the given items."""
        for item in items:
            item_api_base, item_id_key = self._get_api_details(item, item_type)
            self._add_tags(item_api_base, item[item_id_key], tags)

    def process(self):
        """Process all of the data."""
        self.tcex.jobs.process(self.owner)
