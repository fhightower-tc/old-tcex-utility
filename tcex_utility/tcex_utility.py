#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Utility for TCEX."""

try:
    import ConfigParser
except:
    import configparser as ConfigParser
import hashlib
import random
import sys
import uuid

from tcex import TcEx

INDICATOR_BASE_TEMPLATES = {
    'Address': '1.2.{}.{}',
    'EmailAddress': '{}@example.com',
    'File': '{}',
    'Host': '{}.com',
    'Url': 'https://{}.com/'
}


class Util(object):
    def __init__(self, owner=None):
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
        if owner is not None:
            self.tcex.args.api_default_org = owner

    def _authenticate(self):
        config = ConfigParser.RawConfigParser()
        config.read('./tc.conf')

        try:
            api_access_id = config.get('threatconnect', 'api_access_id')
            api_secret_key = config.get('threatconnect', 'api_secret_key')
            api_default_org = config.get('threatconnect', 'api_default_org')
            api_base_url = config.get('threatconnect', 'api_base_url')
        except ConfigParser.NoOptionError:
            print('Could not read configuration file.')
            sys.exit(1)

        self.tcex.args.api_access_id = api_access_id
        self.tcex.args.api_secret_key = api_secret_key
        self.tcex.args.tc_api_path = api_base_url
        if self.tcex.args.api_default_org is None:
            self.tcex.args.api_default_org = api_default_org

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

    def add_default_metadata(self, metadata, object_type):
        """Add metadata which will be added to all objects of the given type."""
        # TODO: add validation to make sure the object_type is valid
        self.default_metadata[object_type] = metadata

    def set_owner(self, owner_name):
        """Set the owner for TCEX."""
        self.tcex.args.api_default_org = owner_name

    def create_multiple_groups(self, count=100, base_name='Test Group', group_type='Incident'):
        """Create the number of groups specified by the count."""
        for x in range(0, count):
            self._create_group(group_type, group_name=base_name + ' {}'.format(x))

    def create_from_symbolic_pattern(self, pattern, count=1):
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

    def finish(self):
        """Finish and process all of the data."""
        self.tcex.jobs.process(self.tcex.args.api_default_org)
