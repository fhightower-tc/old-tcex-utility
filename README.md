# TCEX Utility

Utility for TCEX.

## Usage

Coming soon...

## Examples

### Creating Content from Symbolic Structure

This example will create the following objects 10 times:

A signature, document, incident, and file. The signature will be associated with the document and the incident. The document will be associated with the incident and the file. The incident will be associated with the file.

```python
from tcex_elements import Elements
u = Elements('testing-lab')
u.create_from_symbolic_pattern('sig=doc=inc-file', 10)
u.process()
```

### Get Indicators by Type

```python
from tcex_elements import Elements
u = Elements('testing-lab')
a = u.get_indicators('Address')
print(len(a))
```

### Get Items with a Given Attribute

```python
from tcex_molecules import Molecules
u = Molecules('testing-lab')
a = u.get_items_by_attribute({"type": "Description", "value": "this is just a test"}, 'Address')
```

### Add Attribute to Items with a Given Attribute

```python
from tcex_molecules import Molecules
u = Molecules('testing-lab')
a = u.add_attributes_to_items_by_attribute([{"type": "Description", "value": "New attribute"}], 'Address', {"type": "Description", "value": "this is just a test"})
```

### Add Attributes to Items with a Given Tag

```python
from tcex_molecules import Molecules
u = Molecules('testing-lab')
a = u.add_attributes_to_items_by_tag([{"type": "Description", "value": "this is just a test"}], 'Address', 'Test Tag')
```

## Credits

This package was created with [Cookiecutter](https://github.com/audreyr/cookiecutter) and fhightower's [Python project template](https://github.com/fhightower-templates/python-project-template).
