# Documents Commit
Working with ThreatConnect Document Resources.

## Add an Document Resource

```python
...

tc = ThreatConnect(api_access_id, api_secret_key, api_default_org, api_base_url)

documents = tc.documents()
    
owner = 'Example Community'
document = documents.add('New Document', owner)
document.add_attribute('Description', 'Description Example')
document.add_tag('EXAMPLE')
document.set_security_label('TLP Green')
try:
    document.commit()
except RuntimeError as e:
    print('Error: {0}'.format(e))
    sys.exit(1)
```

### Code Highlights

Snippet                                   | Description                                                                       |
----------------------------------------- | --------------------------------------------------------------------------------- |
`tc = ThreatConnect(api_access_id,...`    | Instantiate the ThreatConnect object. |
`documents = tc.documents()`          | Instantiate an Documents container object. |
`document = documents.add('New Ads...` | Add a resource object setting the name and owner. |
`document.add_attribute('Description...` | Add an Attribute of type 'Description' to the Resource. |
`document.add_tag('EXAMPLE')`            | Add a Tag to the Resource. |
`document.set_security_label('TLPGre...` | Add a Security Label to the Resource. |
`document.commit()`                      | Trigger multiple API calls to write Resource, Attributes, Security Labels, and Tags. |

## Update an Document Resource

```python
...

tc = ThreatConnect(api_access_id, api_secret_key, api_default_org, api_base_url)

documents = tc.documents()

owner = 'Example Community'
document = documents.add('Updated Document', owner)
document.set_id('20')

document.load_attributes()
for attribute in document.attributes:
    if attribute.type == 'Description':
        document.delete_attribute(attribute.id)

document.add_attribute('Description', 'Updated Description')

document.load_tags()
for tag in document.tags:
    document.delete_tag(tag.name)

document.add_tag('EXAMPLE')

try:
    document.commit()
except RuntimeError as e:
    print('Error: {0}'.format(e))
    sys.exit(1)

```

### Code Highlights

Snippet                                   | Description                                                                       |
----------------------------------------- | --------------------------------------------------------------------------------- |
`tc = ThreatConnect(api_access_id,...`    | Instantiate the ThreatConnect object. |
`documents = tc.documents()`          | Instantiate an Documents container object. |
`document = documents.add('Updated...` | Add a resource object setting the name and owner. |
`document.set_id('20')`                  | Set the ID of the Document to the **EXISTING** document ID to update. |
`document.load_attributes()`             | Load existing attributes into the Document object. |
`document.delete_attribute(attribute.id)`| Add delete flag on the attribute with type 'Description'. |
`document.add_attribute('Description...` | Add an Attribute of type 'Description' to the Resource. |
`document.load_tags()`                   | Load existing tags into the Document object. |
`document.delete_tag(tag.name)`          | Add delete flag on to all Tags. |
`document.add_tag('EXAMPLE')`            | Add a Tag to the Resource. |
`document.commit()`                      | Trigger multiple API calls to update/delete Resource, Attributes, and Tags. |

## Delete an Document Resource

```python
...

tc = ThreatConnect(api_access_id, api_secret_key, api_default_org, api_base_url)

documents = tc.documents()

document = documents.add('', owner)
document.set_id(dl_id)

# delete this resource
try:
    resource.delete()
except RuntimeError as e:
    print(e)

```

### Code Highlights

Snippet                                   | Description                                                                       |
----------------------------------------- | --------------------------------------------------------------------------------- |
`tc = ThreatConnect(api_access_id,...`    | Instantiate the ThreatConnect object. |
`documents = tc.documents()`          | Instantiate an Documents container object. |
`document = documents.add('Updated...` | Add a resource object setting the name and owner. |
`document.set_id('20')`                  | Set the ID of the Document to the **EXISTING** document ID to delete. |
`document.delete()`                      | Trigger API calls to delete Resource. |
