#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Basic, elemental functions for TCEX."""

import collections
try:
    import ConfigParser
except:
    import configparser as ConfigParser
import hashlib
import json
import os
import random
import sys
import urllib
import uuid

from tcex import TcEx

from .utility import get_api_details, standardize_item_type, is_group, is_indicator, get_api_base_from_type, get_type_from_weblink, get_indicator_id_key, GROUP_ABBREVIATIONS, INDICATOR_ABBREVIATIONS, INDICATOR_BASE_TEMPLATES

API_VERSION = 'v2'

Attribute = collections.namedtuple('Attribute', ['type', 'value'])
FileOccurrence = collections.namedtuple('FileOccurrence', ['name', 'path', 'date'])


class Elements(object):

    def __init__(self, owner=None, tcex_instance=None, process_logs=False):
        self.owner = owner
        self.process_logs = process_logs
        if tcex_instance is not None:
            self.tcex = tcex_instance
        else:
            self.tcex = TcEx()
            self._authenticate()
            self._set_logging()
        self.default_metadata = dict()

    #
    # MISC FUNCTIONS
    #

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

    def _set_logging(self):
        # this will output the logs in stdout (handy when using a terminal)
        self.tcex.log = self.tcex._logger(True)
        # this will write logs into `./app.log`
        if self.process_logs:
            self.tcex.args.tc_log_level = 'warning'
            self.tcex.args.tc_log_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "."))
            self.tcex.args.tc_out_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "."))
            self.tcex.args.tc_log_to_api = False
            # this is necessary to reinitialize the logger after the parameter(s) was changed in the line(s) above
            self.tcex.log = self.tcex._logger(False)
            # this is a hack to clear the current log because I can't easily change the mode of the logger used by tcex
            with open(self.tcex.log.handlers[-1].baseFilename, 'w') as f:
                f.write('')

    def add_default_metadata(self, object_type, metadata):
        """Add metadata which will be added to all objects of the given type."""
        object_type = standardize_item_type(object_type)
        if is_group(object_type) or is_indicator(object_type):
            self.default_metadata[object_type] = metadata
        else:
            raise ValueError('The object type "{}" is neither a group nor an indicator. Please make sure the object type you provided is correct'.format(object_type))


    def _check_for_default_metdata(self, object_type, object_data):
        """See if there is metadata for objects of the given type and if so, add it to the object's data."""
        object_type = standardize_item_type(object_type)
        if self.default_metadata.get(object_type):
            if self.default_metadata[object_type].get('attributes'):
                if object_data.get('attribute'):
                    object_data['attribute'].extend(self.default_metadata[object_type].get('attributes'))
                else:
                    object_data['attribute'] = self.default_metadata[object_type].get('attributes')
            if self.default_metadata[object_type].get('tags'):
                if object_data.get('tag'):
                    object_data['tag'].extend(self.default_metadata[object_type].get('tags'))
                else:
                    object_data['tag'] = self.default_metadata[object_type].get('tags')
            if self.default_metadata[object_type].get('eventDate'):
                object_data['eventDate'] = self.default_metadata[object_type].get('eventDate')
        return object_data

    def _make_api_request(self, method, api_path, body={}, include_attributes=False, include_tags=False):
        # TODO: implement the functionality for include_associations in this function
        """Make an api request."""
        r = self.tcex.request_tc()
        r.url = '{}/{}/{}'.format(self.tcex.args.tc_api_path, API_VERSION, api_path)
        r.add_header('Content-Type', 'application/json')
        r.add_payload('owner', self.owner)
        r.add_payload('resultLimit', 10000)
        if include_attributes:
            r.add_payload('includeAttributes', 'true')
        if include_tags:
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
            raise RuntimeError('{} response from {} request to {}: {}'.format(response.status_code, method, r.url, response.text))

    def _get_iso_date_format(self, date):
        """Return the iso format (with a trailing 'Z') of the given date."""
        return self.tcex.utils.format_datetime(date, date_format='%Y-%m-%dT%H:%M:%S') + 'Z'

    def set_owner(self, owner_name):
        """Set the owner for TCEX."""
        self.owner = owner_name

    @staticmethod
    def _deduplicate_attributes(existing_item_attributes, new_attributes=None):
        """Deduplicate the item's existing attributes with the ones that we are planning to add."""
        # add the existing attributes
        existing_attributes_set = set([Attribute(attr['type'], attr['value']) for attr in existing_item_attributes])
        # find the new attributes
        if new_attributes:
            new_attributes_set = set([Attribute(attr['type'], attr['value']) for attr in new_attributes]) - existing_attributes_set
        else:
            new_attributes_set = existing_attributes_set
        # TODO: it is probably not the best idea to indiscriminately set the displayed value (as done in the line below), but this will work for now
        deduplicated_attributes_list = [{'type': attr.type, 'value': attr.value, 'displayed': True} for attr in new_attributes_set]
        return deduplicated_attributes_list

    @staticmethod
    def _deduplicate_file_occurrences(existing_file_occurrences, new_file_occurrences, indicator_summary):
        # add the existing file occurrences
        existing_file_occurrences_set = set([FileOccurrence(fo.get('fileName'), fo.get('path'), fo.get('date').split('T')[0]) for fo in existing_file_occurrences])
        # find the new file occurrences
        new_file_occurrences_set = set([FileOccurrence(fo.get('fileName'), fo.get('path'), fo.get('date').split('T')[0]) for fo in new_file_occurrences if fo['hash'] in indicator_summary]) - existing_file_occurrences_set
        only_new_file_occurrences_list = [{
            'fileName': fo.name,
            'path': fo.path,
            'date': fo.date,
            'hash': indicator_summary.split(' :')[0]
        } for fo in new_file_occurrences_set]
        return only_new_file_occurrences_list

    def _handle_deduplication(self, dont_create_duplicate_groups=False):
        for indicator_json in self.tcex.jobs._indicators:
            # check if item already exists in TC
            try:
                if standardize_item_type(indicator_json['type']) == 'file' and ' : ' in indicator_json['summary']:
                    existing_item = self.get_item(indicator_json['type'], indicator_json['summary'].split(' : ')[0], include_attributes=True, include_file_occurrences=True)
                else:
                    existing_item = self.get_item(indicator_json['type'], indicator_json['summary'], include_attributes=True, include_file_occurrences=True)
            # if a `RuntimeError` is raised, assume the request failed which means the item does not exist
            except RuntimeError as e:
                continue
            else:
                # if the item exists and it has attributes and the new version of the item also has attributes: deduplicate the attributes (and file occurrences if applicable)
                if existing_item and existing_item.get('attribute') and indicator_json.get('attribute'):
                    indicator_json['attribute'] = self._deduplicate_attributes(existing_item['attribute'], indicator_json['attribute'])

                # if the indicator is a file type, deduplicate file occurrences
                if existing_item and existing_item.get('fileOccurrences') and self.tcex.jobs._file_occurrences:
                    self.tcex.jobs._file_occurrences = self._deduplicate_file_occurrences(existing_item['fileOccurrences'], self.tcex.jobs._file_occurrences, indicator_json['summary'])

        if dont_create_duplicate_groups:
            deduplicated_group_list = list()
            for group_json in self.tcex.jobs._groups:
                # check if item already exists in TC
                try:
                    existing_item = self.get_item(group_json['type'], group_json['name'])
                # if a `RuntimeError` is raised, assume the request failed which means the item does not exist
                except RuntimeError as e:
                    # if there is no group with the current group's name, record the group
                    deduplicated_group_list.append(group_json)
                else:
                    # if a group with this name already exists TC, don't create a duplicate
                    pass
            self.tcex.jobs._groups = deduplicated_group_list

    def run_log_processing(self):
        """Look through the logs to find certain errors."""
        error_identifiers = {
            'invalid_indicator': ['Failed adding indicator', 'Please enter a valid'],
            # TODO: are there exclusion lists at any level other than the system level?
            'exclusion_list_failure': ['Failed adding indicator', 'This indicator is contained on a system-wide exclusion list']
        }
        errors = {
            'invalid_indicator': list(),
            'exclusion_list_failure': list()
        }

        with open(self.tcex.log.handlers[-1].baseFilename, 'r') as f:
            file_text = f.read()

        for line in file_text.split('\n'):
            for key, patterns in error_identifiers.items():
                all_patterns_found = True
                for pattern in patterns:
                    if pattern not in line:
                        all_patterns_found = False
                        break
                if all_patterns_found:
                    errors[key].append(line)
        return errors

    def process(self, indicator_batch=False, deduplicate_content=True, dont_create_duplicate_groups=False):
        """Process all of the data."""
        if deduplicate_content:
            try:
                self._handle_deduplication(dont_create_duplicate_groups)
            except Exception as e:
                # this is added primarily to continue execution if there are encoding errors on TC versions which are still running python2
                self.tcex.log.error('Exception while attempting to deduplicate: {}'.format(e))
        self.tcex.jobs.process(self.owner, indicator_batch=indicator_batch)
        if self.process_logs:
            errors = self.run_log_processing()
            return errors

    def create_from_tcex_json(self, tcex_json, indicator_batch=False, deduplicate_content=True):
        """Create the given data in ThreatConnect.

        Inputs:
            - tcex_json: This value is a dictionary with the possible keys:
                - 'groups': A list of groups represented by json in the format described here: https://docs.threatconnect.com/en/latest/tcex/jobs.html#groups

                - 'indicators': A list of indicators represented by json in the format described here: https://docs.threatconnect.com/en/latest/tcex/jobs.html#indicators

                - 'victims': A list of victims represented by json in the format described here: https://docs.threatconnect.com/en/latest/rest_api/victims/victims.html#create-victims with the option to have an array with the key `attributes` and/or `tags` containing attributes and tags.

                - 'file_occurrences': A list of file occurrences represented by json in the format described here: https://docs.threatconnect.com/en/latest/tcex/jobs.html#file-occurrence

                - 'group_to_indicator_associations': A list of group-to-indicator associations represented by json in the format described here: https://docs.threatconnect.com/en/latest/tcex/jobs.html#group-to-indicator-associations

                - 'group_to_group_associations': A list of group-to-group associations represented by json in the format described here: https://docs.threatconnect.com/en/latest/tcex/jobs.html#group-to-group-associations

                - 'indicator_to_indicator_associations': A list of indicator-to-indicator associations represented by json in the format described here: https://docs.threatconnect.com/en/latest/tcex/jobs.html#indicator-to-indicator-associations
        """
        if tcex_json.get('groups'):
            for group_json in tcex_json['groups']:
                self.tcex.jobs.group(group_json)
        if tcex_json.get('indicators'):
            for indicator_json in tcex_json['indicators']:
                self.tcex.jobs.indicator(indicator_json)
        if tcex_json.get('victims'):
            for victim in tcex_json['victims']:
                attributes = None
                tags = None
                # add attributes to the victim
                if victim.get('attributes'):
                    attributes = victim['attributes']
                    del victim['attributes']
                # add tags to the victim
                if victim.get('tags'):
                    tags = victim['tags']
                    del victim['tags']
                # create the victim
                response = self._make_api_request('POST', 'victims', victim)
                # this is necessary to add attributes and tags
                response['victim']['type'] = 'Victim'
                # add attributes to the victim
                if attributes is not None:
                    self.add_attributes([response['victim']], attributes)
                # add tags to the victim
                if tags is not None:
                    self.add_tags([response['victim']], tags)
        if tcex_json.get('file_occurrences'):
            for file_occurrence_json in tcex_json['file_occurrences']:
                self.tcex.jobs.file_occurrence(file_occurrence_json)
        if tcex_json.get('group_to_indicator_associations'):
            for group_association_json in tcex_json['group_to_indicator_associations']:
                self.tcex.jobs.group_association(group_association_json)
        if tcex_json.get('group_to_group_associations'):
            for group_association_json in tcex_json['group_to_group_associations']:
                self.tcex.jobs.association(group_association_json)
        if tcex_json.get('indicator_to_indicator_associations'):
            for indicator_association_json in tcex_json['indicator_to_indicator_associations']:
                self.tcex.jobs.association(indicator_association_json)
        self.process(indicator_batch, deduplicate_content)

    #
    # GROUPS
    #

    def create_group(self, group_type, group_name=None):
        """Create a group."""
        group_data = self.create_group_data(group_type, group_name)
        group_data = self._check_for_default_metdata(group_type, group_data)
        self.tcex.jobs.group(group_data)
        return group_data

    def create_group_from_tcex_json(self, group_json):
        """Create a group from the given tcex json."""
        if group_json.get('type'):
            group_json = self._check_for_default_metdata(standardize_item_type(group_json['type']), group_json)
        else:
            group_json = self._check_for_default_metdata(get_type_from_weblink(group_json['webLink']), group_json)
        self.tcex.jobs.group(group_json)
        return group_json

    def create_groups_from_tcex_json(self, groups_json):
        """Create the groups from the given tcex json containing data for multiple groups."""
        for group_json in groups_json:
            self.create_group_from_tcex_json(group_json)

    def create_group_data(self, group_type, group_name):
        # if no group name is given, create one with a uuid
        if group_name == '' or group_name is None:
            group_name = 'Test {} {}'.format(group_type, str(uuid.uuid4()).split('-')[0])
        group_json = {
            'name': group_name,
            'type': group_type
        }
        # TODO: is it possible to create an incident using this function?
        warning_message = 'You are creating a {} which requires special data. I\'ll add it for you, but you may want to check to make sure this is correct.'.format(group_type)
        if group_type == 'Document':
            print(warning_message)
            group_json['fileData'] = 'Test document'
            group_json['fileName'] = 'test.txt'
        elif group_type == 'Signature':
            print(warning_message)
            group_json['fileName'] = 'test.yara'
            group_json['fileText'] = 'Test Signature'
            group_json['fileType'] = 'YARA'
        return group_json

    def create_test_groups(self, group_type='Incident', base_name='Test Group', count=100):
        """Create the number of groups specified by the count."""
        for x in range(0, count):
            self.create_group(group_type, None)

    #
    # GROUPS: INCIDENTS
    #

    def set_event_date(self, incident_id, event_date):
        """Set the event date for the incident with the given id."""
        request_body = {
            'eventDate': self._get_iso_date_format(event_date)
        }
        self._make_api_request('PUT', 'groups/incidents/{}'.format(incident_id), request_body)

    def set_event_dates(self, incidents, event_date):
        """Set the event dates for the given incidents."""
        for incident in incidents:
            self.set_event_date(incident['id'], event_date)

    #
    # INDICATORS
    #

    def create_indicator_from_tcex_json(self, indicator_json):
        """Create an indicator from the given tcex json."""
        pass
        # TODO: implement!

    def create_indicators_from_tcex_json(self, indicators_json):
        """Create the indicators from the given tcex json containing data for multiple indicators."""
        for indicator_json in indicators_json:
            self.create_indicator_from_tcex_json(indicator_json)

    def create_indicator(self, indicator_type, indicator_summary=None):
        """Create an indicator given and indicator type and the indicator summary."""
        if indicator_summary is None:
            indicator_summary = self.create_test_indicator_summary(indicator_type)
        indicator_data = {
            'summary': indicator_summary,
            'type': indicator_type
        }
        indicator_data = self._check_for_default_metdata(indicator_type, indicator_data)
        self.tcex.jobs.indicator(indicator_data)
        # this is done to normalize the group and indicator data... it may be better to do this in another function
        indicator_data['name'] = indicator_data['summary']
        return indicator_data

    def create_test_indicator_summary(self, indicator_type):
        """Create a test indicator of the given type."""
        host_base = str(uuid.uuid4()).split('-')[0]
        base_indicator = INDICATOR_BASE_TEMPLATES[indicator_type.lower()]

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

    def delete_indicator(self, indicator_type, indicator_summary):
        # TODO: make a separate function to do this:
        if indicator_type.lower() == 'file':
            indicator_summary = indicator_summary.split(':')[0].strip()
        elif indicator_type.lower() == 'url':
            indicator_summary = urllib.parse.quote_plus(indicator_summary.encode('utf-8'))
        self._make_api_request('DELETE', '{}/{}'.format(get_api_base_from_type(indicator_type), indicator_summary))

    #
    # ASSOCIATIONS
    #

    def create_association(self, object1, object2, custom_association_name=''):
        """Create an association between the two objects."""
        if not object1.get('type'):
            object1['type'] = get_type_from_weblink(object1['webLink'])

        if not object2.get('type'):
            object2['type'] = get_type_from_weblink(object2['webLink'])

        if is_group(object1['type']):
            # group to group association
            if is_group(object2['type']):
                self.tcex.jobs.association({
                    "association_value": object1['name'],
                    "association_type": object1['type'].title(),
                    "resource_value": object2['name'],
                    "resource_type": object2['type'].title()
                })
            # group to indicator association
            else:
                self.tcex.jobs.group_association({
                    "group_name": object1['name'],
                    "group_type": object1['type'].title(),
                    "indicator": object2['name'],
                    "indicator_type": object2['type'].title()
                })
        else:
            # indicator to group association
            if is_group(object2['type']):
                self.tcex.jobs.group_association({
                    "group_name": object2['name'],
                    "group_type": object2['type'].title(),
                    "indicator": object1['name'],
                    "indicator_type": object1['type'].title()
                })
            # indicator to indicator association
            else:
                # TODO: implement this feature so that custom indicator to indicator associations can be created - is this done?
                self.tcex.jobs.association({
                    "association_value": object1['name'],
                    "association_type": tcex.safe_rt(object1['type'].title()),
                    "resource_value": object2['name'],
                    "resource_type": tcex.safe_rt(object2['type'].title()),
                    "custom_association_name": custom_association_name
                })
            # TODO: handle file action associations

    #
    # ATTRIBUTES
    #

    def add_attributes(self, tcex_json_items, attributes_list):
        """Add attributes to the given tcex_json_items."""
        for item in tcex_json_items:
            # TODO: why is the 'if' statement below necessary? standardization should be done automatically when data comes in/out
            if item.get('webLink'):
                item_api_base, item_id_key = get_api_details(item)
            else:
                item_api_base = get_api_base_from_type(item['type'])
                item_id_key = 'summary'
            self._add_attributes(item_api_base, item[item_id_key], attributes_list)

    def _add_attributes(self, item_api_base, item_id, attributes_list):
        """Add the attributes to the given item."""
        for attribute in attributes_list:
            self._make_api_request('POST', '{}/{}/attributes'.format(item_api_base, item_id), attribute)

    def delete_attributes(self, tcex_json_item, attribute_id):
        item_api_base, item_id_key = get_api_details(tcex_json_item)
        api_path = '{}/{}/attributes/{}'.format(item_api_base, tcex_json_item[item_id_key], attribute_id)
        results = self._make_api_request('DELETE', api_path)
        return results

    #
    # SECURITY LABELS
    #

    # TODO: consolidate add_attributes, add_sec_labels, and add_tags functions (see the TODO in the `add_attributes` function first, though)
    def add_sec_labels(self, items, sec_labels):
        """Add security labels to the given items."""
        for item in items:
            item_api_base, item_id_key = get_api_details(item)
            self._add_sec_labels(item_api_base, item[item_id_key], sec_labels)

    def _add_sec_labels(self, item_api_base, item_id, sec_labels):
        """Add the security labels to the given item."""
        for label in sec_labels:
            self._make_api_request('POST', '{}/{}/securityLabels/{}'.format(item_api_base, item_id, label))

    def get_sec_labels(self, item):
        """Get security labels for the given item."""
        item_api_base, item_id_key = get_api_details(item)
        return self._make_api_request('GET', '{}/{}/securityLabels'.format(item_api_base, item[item_id_key]))

    #
    # TAGS
    #

    def add_tags(self, items, tags):
        """Add tags to the given items."""
        for item in items:
            item_api_base, item_id_key = get_api_details(item)
            self._add_tags(item_api_base, item[item_id_key], tags)

    def remove_tags(self, items, tags):
        for item in items:
            for tag in tags:
                self.remove_tag(item, tag)

    def _add_tags(self, item_api_base, item_id, tags):
        """Add the tags to the given item."""
        for tag in tags:
            self._make_api_request('POST', '{}/{}/tags/{}'.format(item_api_base, item_id, tag))

    def remove_tag(self, item, tag):
        item_api_base, item_id_key = get_api_details(item)
        api_path = '{}/{}/tags/{}'.format(item_api_base, item[item_id_key], tag)
        results = self._make_api_request('DELETE', api_path)
        return results

    def delete_tag(self, tag):
        api_path = 'tags/{}'.format(tag)
        results = self._make_api_request('DELETE', api_path)
        return results

    #
    # PUBLICATION
    #

    def publish_group(self, group_type, group_id, security_label_list=[], exclude_unlabeled=False):
        self._make_api_request('POST', '{}/{}/publish'.format(get_api_base_from_type(group_type), group_id), {
            "securityLabelList": security_label_list,
            "excludeUnlabeled": exclude_unlabeled
        })

    #
    # GENERIC RETRIEVAL
    #

    def get_items_by_type(self, item_type=None, include_attributes=False, include_tags=False):
        """Get all items of the given type."""
        items = list()
        # if there is no reason to make an API call, just use the tcex.resource library
        if item_type is not None and item_type.lower() != 'victim' and not include_attributes and not include_tags:
            item_type = standardize_item_type(item_type)
            # make sure the first character in the type is uppercased (so that it will work with TCEX)
            item_type = item_type[0].title() + item_type[1:]
            item_data = self.tcex.resource(item_type)
            item_data.owner = self.owner
            # paginate over results
            for entry in item_data:
                for item in entry['data']:
                    # record the type of the item
                    item['type'] = get_type_from_weblink(item['webLink'])
                    # record the indicator itself to the standardized key: 'name'
                    item['name'] = item[get_indicator_id_key(item)]
                    items.append(item)
            return items
        # if we want to get attributes and/or tags, make an API request
        else:
            if item_type is None or item_type.lower() == 'all':
                # get all indicators
                items.extend(self.get_items_by_type('indicators', include_attributes=include_attributes, include_tags=include_tags))
                # get all groups
                items.extend(self.get_items_by_type('groups', include_attributes=include_attributes, include_tags=include_tags))
                return items
            elif item_type.lower() == 'indicators':
                for indicator_type in INDICATOR_ABBREVIATIONS.values():
                    new_items = self.get_items_by_type(indicator_type, include_attributes=include_attributes, include_tags=include_tags)
                    if new_items is not None:
                        items.extend(new_items)
                return items
            elif item_type.lower() == 'groups':
                for group_type in GROUP_ABBREVIATIONS.values():
                    items.extend(self.get_items_by_type(group_type, include_attributes=include_attributes, include_tags=include_tags))
                return items
            else:
                item_api_base, item_id_key = get_api_details({'type': item_type})
                results = self._make_api_request('GET', item_api_base, include_attributes=include_attributes, include_tags=include_tags)
                items = results.get(standardize_item_type(item_type))
                # record the type of the item
                for item in items:
                    item['type'] = get_type_from_weblink(item['webLink'])
            return items

    def get_item(self, item_type, item_id, include_attributes=False, include_tags=False, include_file_occurrences=False, include_associations=False):
        """Get the single item of the given type based on the given id."""
        # if there is no reason to make an API call, just use the tcex.resource library
        if not include_attributes and not include_tags and not include_file_occurrences and not include_associations:
            item_type = standardize_item_type(item_type)
            # make sure the first character in the type is uppercased (so that it will work with TCEX)
            item_type = item_type[0].title() + item_type[1:]
            item_data = self.tcex.resource(item_type)
            item_data.owner = self.owner
            item_data.resource_id(item_id)
            item = [item for item in item_data]
            return item[0]['data']
        # if we want to get attributes and/or tags, make an API request
        else:
            base_api_path = get_api_base_from_type(item_type)
            if isinstance(item_id, str):
                if item_type.lower() == 'file':
                    self.tcex.log.debug("item_type.lower() {}".format(item_type.lower()))
                    item_id = item_id.split(':')[0].strip()
                    self.tcex.log.debug("item_id {}".format(item_id))
                item_id = urllib.parse.quote_plus(item_id.encode('utf-8'))
            results = self._make_api_request('GET', '{}/{}'.format(base_api_path, item_id), include_attributes=include_attributes, include_tags=include_tags)
            item = results.get(standardize_item_type(item_type))
            item['type'] = standardize_item_type(item_type)
            item['name'] = item[get_indicator_id_key(item)]

            if include_file_occurrences and standardize_item_type(item_type) == 'file':
                fileOccurrences = self._make_api_request('GET', '{}/{}/fileOccurrences'.format(base_api_path, item_id))
                item['fileOccurrences'] = fileOccurrences['fileOccurrence']

            if include_associations:
                item['associations'] = dict()

                group_associations = self._make_api_request('GET', '{}/{}/groups/'.format(base_api_path, item_id))['group']
                item['associations']['groups'] = group_associations

                indicator_associations = self._make_api_request('GET', '{}/{}/indicators/'.format(base_api_path, item_id))['indicator']
                item['associations']['indicators'] = indicator_associations

            return item
