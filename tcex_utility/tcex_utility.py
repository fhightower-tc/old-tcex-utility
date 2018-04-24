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

    def _create_group(self, group_name='', group_type='Incident'):
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


    def _create_indicator(self, indicator='', indicator_type='Address'):
        if indicator == '':
            indicator = self._generate_test_indicator(indicator_type)
        indicator_data = {
            'summary': indicator,
            'type': indicator_type
        }
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

    def set_owner(self, owner_name):
        """Set the owner for TCEX."""
        self.tcex.args.api_default_org = owner_name

    def create_multiple_groups(self, count=100, base_name='Test Group', group_type='Incident'):
        """Create the number of groups specified by the count."""
        for x in range(0, count):
            self._create_group(group_name=base_name + ' {}'.format(x), group_type=group_type)

    def create_from_semiositic_pattern(self, pattern, count=1):
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
                    created_objects.append(self._create_group(group_type=self.group_abbreviations[obj]))
                elif obj in self.indicator_abbreviations:
                    created_objects.append(self._create_indicator(indicator_type=self.indicator_abbreviations[obj]))

            if len(associations) > 0:
                # create associations
                for i in range(0, len(created_objects) - 1):
                    self._create_association(created_objects[i], created_objects[i + 1])
                    if associations[i] == '=':
                        self._create_association(created_objects[i], created_objects[i + 2])

    def finish(self):
        """Finish and process all of the data."""
        self.tcex.jobs.process(self.tcex.args.api_default_org)
