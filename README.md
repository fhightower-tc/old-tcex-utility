# TCEX Utility

Utility for TCEX.

## Usage

Coming soon...

## Examples

### Creating Content from Symbolic Structure

This example will create the following objects 10 times:

A signature, document, incident, and file. The signature will be associated with the document and the incident. The document will be associated with the incident and the file. The incident will be associated with the file.

```python
from tcex_utility import Util
u = Util('testing-lab')
u.create_from_symbolic_pattern('sig=doc=inc-file', 10)
u.process()
```

### Retrieving Indicators

```python
from tcex_utility import Util
u = Util('testing-lab')
a = u.get_indicators('Address')
print(len(a))
```

## Credits

This package was created with [Cookiecutter](https://github.com/audreyr/cookiecutter) and fhightower's [Python project template](https://github.com/fhightower-templates/python-project-template).
