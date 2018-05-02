#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Relatively complex functions (known as 'Molecules') performed using the underlying 'Elements'."""

from tcex_elements import Elements


class Molecules(Elements):
    def __init__(self, owner=None):
        self.owner = owner
        super(Molecules, self).__init__()

    def add_attributes_to_all_items_of_type(self, attributes, item_type):
        """Add the given attributes to all items of the given type."""
        items = self.get_items(item_type)
        self.add_attributes(attributes, items, item_type)
