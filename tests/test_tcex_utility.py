#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
test_tcex_utility
----------------------------------

Tests for `tcex_utility` module.
"""
import pytest


from tcex_utility import tcex_utility


@pytest.fixture
def absolute_path():
    """Return an absolute path (which is useful for running tests)."""
    # return os.path.abspath(os.path.join(os.path.dirname(__file__), '.'))


@pytest.fixture
def response():
    """Sample pytest fixture.
    See more at: http://doc.pytest.org/en/latest/fixture.html
    """
    # import requests
    # return requests.get('https://github.com/audreyr/cookiecutter-pypackage')


def test_content(absolute_path, response):
    """Sample pytest test function with the pytest fixture as an argument.
    """
    # from bs4 import BeautifulSoup
    # assert 'GitHub' in BeautifulSoup(response.content).title.string
