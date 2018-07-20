#!/usr/bin/env python
# -*- coding: utf-8 -*-

from democritus.elements import Elements

OWNER = 'Research Labs'


def test_create_group_from_tcex_json():
    e = Elements(OWNER)
    data = {
      "attribute": [
        {
          "type": "Description",
          "value": "Test Description"
        }
      ],
      "name": "Robin Sparkles",
      "tag": [
        {
          "name": "APT"
        },{
          "name": "CrimeWare"
        }
      ],
      "type": "Adversary"
    }
    e.create_group_from_tcex_json(data)
    e.process()
