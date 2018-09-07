#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Relatively complex functions (known as 'Molecules') performed using the underlying 'Elements'."""
from datetime import datetime

from .elements import Elements
from .utility import get_type_from_weblink, GROUP_ABBREVIATIONS, INDICATOR_ABBREVIATIONS


class Molecules(Elements):

    def __init__(self, owner=None, tcex_instance=None):
        self.owner = owner
        super(Molecules, self).__init__(owner=owner, tcex_instance=tcex_instance)

    #
    # RETRIEVAL FUNCTIONS
    #

    def get_items_by_attribute(self, item_attribute, item_type=None):
        """Find all items with the given attribute."""
        results = self.get_items_by_type(item_type=item_type, include_attributes=True)
        items = list()

        for result in results:
            if result.get('attribute'):
                for existing_attribute in result['attribute']:
                    if item_attribute['type'] == existing_attribute['type']:
                        if item_attribute.get('value'):
                            if item_attribute['value'] == existing_attribute['value']:
                                items.append(result)
                        else:
                            items.append(result)
        return items

    def get_items_by_sec_label(self, item_sec_label, item_type=None):
        """Find all items with the given security label."""
        results = self.get_items_by_type(item_type=item_type)
        items = list()

        for result in results:
            sec_labels = [sec_label['name'] for sec_label in self.get_sec_labels(result)['securityLabel']]
            if item_sec_label in sec_labels:
                items.append(result)
        return items

    def get_items_by_tag(self, item_tag, item_type=None):
        """Find all items with the given tag."""
        results = self.get_items_by_type(item_type=item_type, include_tags=True)
        items = list()

        for result in results:
            if result.get('tag'):
                if item_tag in [tag['name'] for tag in result['tag']]:
                    items.append(result)
        return items

    #
    # ADD ATTRIBUTES
    #

    def add_attributes_to_items_by_type(self, attributes, item_type):
        """Add the given attributes to all items of the given type."""
        items = self.get_items_by_type(item_type=item_type)
        self.add_attributes(items, attributes)
        return items

    def add_attributes_to_items_by_attribute(self, new_attributes, item_attribute, item_type=None):
        """Add the given attributes to all items of the given type."""
        items = self.get_items_by_attribute(item_attribute, item_type)
        self.add_attributes(items, new_attributes)
        return items

    def add_attributes_to_items_by_sec_label(self, attributes, item_sec_label, item_type=None):
        """Add the given attributes to all items with the given security label."""
        items = self.get_items_by_sec_label(item_sec_label, item_type)
        self.add_attributes(items, attributes)
        return items

    def add_attributes_to_items_by_tag(self, attributes, item_tag, item_type=None):
        """Add the given attributes to all items with the given tag."""
        items = self.get_items_by_tag(item_tag, item_type)
        self.add_attributes(items, attributes)
        return items

    #
    # ADD SECURITY LABELS
    #

    def add_sec_labels_to_items_by_type(self, sec_labels, item_type):
        """Add the given security labels to all items of the given type."""
        items = self.get_items_by_type(item_type=item_type)
        self.add_sec_labels(items, sec_labels)
        return items

    def add_sec_labels_to_items_by_attribute(self, new_sec_labels, item_attribute, item_type=None):
        """Add the given security labels to all items with the given attribute."""
        items = self.get_items_by_attribute(item_attribute, item_type)
        self.add_sec_labels(items, new_sec_labels)
        return items

    def add_sec_labels_to_items_by_sec_label(self, new_sec_labels, item_sec_label, item_type=None):
        """Add the given security labels to all items with the given security label."""
        items = self.get_items_by_sec_label(item_sec_label, item_type)
        self.add_sec_labels(items, new_sec_labels)
        return items

    def add_sec_labels_to_items_by_tag(self, new_sec_labels, item_tag, item_type=None):
        """Add the given security labels to all items with the given tag."""
        items = self.get_items_by_tag(item_tag, item_type)
        self.add_sec_labels(items, new_sec_labels)
        return items

    #
    # ADD TAGS
    #

    def add_tags_to_items_by_type(self, tags, item_type):
        """Add the given tags to all items of the given type."""
        items = self.get_items_by_type(item_type=item_type)
        self.add_tags(items, tags)
        return items

    def add_tags_to_items_by_attribute(self, new_tags, item_attribute, item_type=None):
        """Add the given tags to all items with the given attribute."""
        items = self.get_items_by_attribute(item_attribute, item_type)
        self.add_tags(items, new_tags)
        return items

    def add_tags_to_items_by_sec_label(self, new_tags, item_sec_label, item_type=None):
        """Add the given tags to all items with the given security label."""
        items = self.get_items_by_sec_label(item_sec_label, item_type)
        self.add_tags(items, new_tags)
        return items

    def add_tags_to_items_by_tag(self, new_tags, item_tag, item_type=None):
        """Add the given tags to all items with the given tag."""
        items = self.get_items_by_tag(item_tag, item_type)
        self.add_tags(items, new_tags)
        return items

    #
    # ASSOCIATION
    #

    def create_associations_between_two_lists(self, item_list1, item_list2):
        """Create associations between each item at the same index of equal-length arrays."""
        if len(item_list1) != len(item_list2):
            raise RuntimeWarning("The length of the two lists needs to be the same")

        for index, item in enumerate(item_list1):
            self.create_association(item, item_list2[index])

    #
    # MISC FUNCTIONS
    #
    def get_items_by_date(self, item_type=None, date_type='dateAdded', lowerbound="0001-01-01T00:00:00Z", upperbound="9999-12-31T23:59:59Z"):
        """
            Get all items of a specific type between given lowerbound and
            upperbound dates for specific date type.

            date_type can be either dateAdded or lastModified
        """
        if date_type not in ['dateAdded', 'lastModified']:
            raise RuntimeError('Date type not valid. Must be either dateAdded or lastModified.')
        try:
            lower = datetime.strptime(lowerbound, "%Y-%m-%dT%H:%M:%SZ")
            upper = datetime.strptime(upperbound, "%Y-%m-%dT%H:%M:%SZ")
        except ValueError:
            print('Error: Incorrect format for datetime.')
        items = self.get_items_by_type(item_type=item_type, include_attributes=True)
        results = list()
        for item in items:
            item_date = datetime.strptime(item[date_type], "%Y-%m-%dT%H:%M:%SZ")
            if lower < item_date < upper:
                results.append(item)
        return results


    def deduplicate_attributes_on_items(self, items):
        """Deduplicate attributes for a given list of items."""
        for item in items:
            all_attributes = item.get('attribute', [])
            new_attributes = self._deduplicate_attributes(all_attributes)
            for attribute in all_attributes:
                self.delete_attributes(item, attribute.get('id'))
            self.add_attributes([item], new_attributes)

    def update_attributes_on_items(self, old_attribute, new_attribute, items, items_type=None):
        """Change the old_attribute to the new_attribute for all of the given items."""
        # if no attribute type is given for the new attribute, assume it is the same type as the old attribute
        if not new_attribute.get('type'):
            new_attribute['type'] = old_attribute['type']

        for item in items:
            attributes = self.get_attributes(item, items_type)
            for attribute in attributes:
                if attribute['type'] == old_attribute['type']:
                    if attribute.get('value'):
                        if attribute['value'] == old_attribute['value']:
                            self.delete_attribute(item, attribute['id'])
                            self.add_attributes([item], [new_attribute])
                            break
                        else:
                            pass
                    else:
                        self.delete_attribute(item, attribute['id'])
                        self.add_attributes([item], [new_attribute])
                        break

    def replace_tag(self, old_tag, new_tags, item_type=None, delete_old_tag=False):
        """Replace all items tagged with the old_tag with the new_tags and remove the old_tag."""
        items = self.get_items_by_tag(old_tag, item_type)
        self.add_tags(items, new_tags)
        if delete_old_tag:
            self.delete_tag(old_tag)
        else:
            self.remove_tags(items, [old_tag])

    def export_group(self, group_type, group_id):
        """Export the data representing a group."""
        group_json = self.get_item(group_type, group_id, include_attributes=True, include_tags=True)
        group_json['type'] = get_type_from_weblink(group_json['webLink']).title()
        return group_json

    def create_from_symbolic_pattern(self, pattern, count=1):
        """Create groups represented symbolically."""
        # TODO: test this function out to make sure it works - it was moved to molecules.py from elements.py
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
                if obj in GROUP_ABBREVIATIONS:
                    # TODO: this shouldn't have to be `.title()`
                    created_objects.append(self.create_group(GROUP_ABBREVIATIONS[obj].title()))
                elif obj in INDICATOR_ABBREVIATIONS:
                    created_objects.append(self.create_indicator(INDICATOR_ABBREVIATIONS[obj].title()))

            if len(associations) > 0:
                # create associations
                for i in range(0, len(created_objects) - 1):
                    self.create_association(created_objects[i], created_objects[i + 1])
                    if associations[i] == '=':
                        self.create_association(created_objects[i], created_objects[i + 2])
