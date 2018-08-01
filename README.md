# Democritus

Utility functions for TCEX.

## Overview

This package is an abstraction on the [TCEX](https://github.com/ThreatConnect-Inc/tcex) package. There are two, major types of items in this package:

1. Elements - Basic functions that perform a single operation.
2. Molecules - Functions that perform multiple operations often using multiple elements.

## Installation

```
git clone https://gitlab.com/fhightower-tc/democritus.git
cd democritus
pip3 install . --user
```

## Usage

To use an element:

```python
from democritus import Elements
e = Elements(<OWNER_NAME>)
```

To use a molecule:

```python
from democritus import Molecules
m = Molecules(<OWNER_NAME>)
```

## Examples

### Creating Content from Symbolic Structure

This example will create the following objects 10 times:

A signature, document, incident, and file. The signature will be associated with the document and the incident. The document will be associated with the incident and the file. The incident will be associated with the file.

```python
from democritus import Elements
e = Elements('testing-lab')
e.create_from_symbolic_pattern('sig=doc=inc-file', 10)
e.process()
```

### Get Indicators by Type

```python
from democritus import Elements
e = Elements('testing-lab')
a = e.get_items_by_type('Address')
print(len(a))
```

### Get Items with a Given Attribute

```python
from democritus import Molecules
m = Molecules('testing-lab')
a = m.get_items_by_attribute({"type": "Description", "value": "this is just a test"}, 'Address')
```

### Add Attribute to Items with a Given Attribute

```python
from democritus import Molecules
m = Molecules('testing-lab')
a = m.add_attributes_to_items_by_attribute([{"type": "Description", "value": "New attribute"}], 'Address', {"type": "Description", "value": "this is just a test"})
```

### Add Attributes to Items with a Given Tag

```python
from democritus import Molecules
m = Molecules('testing-lab')
a = m.add_attributes_to_items_by_tag([{"type": "Description", "value": "this is just a test"}], 'Address', 'Test Tag')
```

### Associate Two Lists of Items

```python
from democritus.molecules import Molecules
m = Molecules('testing-lab')
inds = m.get_items_by_type('incident')
len(inds) # 10
sigs = m.get_items_by_type('signature')
len(sigs) # 10
m.create_associations_between_two_lists(inds, sigs)
```

### Create Items from a Symbolic Pattern

```python
from democritus.elements import Elements
e = Elements('testing-lab')
e.add_default_metadata('Signature', {
    'attributes': [{
        'type': 'Rule Confidence',
        'value': 'High'
    }, {
        'type': 'Rule Priority',
        'value': 'Medium'
    }]
})
e.create_from_symbolic_pattern('doc=inc=file-sig', 10)
```

For more examples, refer to the `tests/` directory.

## Credits

This package was created with [Cookiecutter](https://github.com/audreyr/cookiecutter) and fhightower's [Python project template](https://gitlab.com/fhightower-templates/python-project-template).
