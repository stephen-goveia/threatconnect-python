# Signatures Commit
Working with ThreatConnect Signature Resources.

## Add an Signature Resource

```python
...

tc = ThreatConnect(api_access_id, api_secret_key, api_default_org, api_base_url)

signatures = tc.signatures()
    
owner = 'Example Community'
signature = signatures.add('New Signature', owner)
signature.add_attribute('Description', 'Description Example')
signature.add_tag('EXAMPLE')
signature.set_security_label('TLP Green')
try:
    signature.commit()
except RuntimeError as e:
    print('Error: {0}'.format(e))
    sys.exit(1)
```

### Code Highlights

Snippet                                   | Description                                                                       |
----------------------------------------- | --------------------------------------------------------------------------------- |
`tc = ThreatConnect(api_access_id,...`    | Instantiate the ThreatConnect object. |
`signatures = tc.signatures()`          | Instantiate an Signatures container object. |
`signature = signatures.add('New Ads...` | Add a resource object setting the name and owner. |
`signature.add_attribute('Description...` | Add an Attribute of type 'Description' to the Resource. |
`signature.add_tag('EXAMPLE')`            | Add a Tag to the Resource. |
`signature.set_security_label('TLPGre...` | Add a Security Label to the Resource. |
`signature.commit()`                      | Trigger multiple API calls to write Resource, Attributes, Security Labels, and Tags. |

## Update an Signature Resource

```python
...

tc = ThreatConnect(api_access_id, api_secret_key, api_default_org, api_base_url)

signatures = tc.signatures()

owner = 'Example Community'
signature = signatures.add('Updated Signature', owner)
signature.set_id('20')

signature.load_attributes()
for attribute in signature.attributes:
    if attribute.type == 'Description':
        signature.delete_attribute(attribute.id)

signature.add_attribute('Description', 'Updated Description')

signature.load_tags()
for tag in signature.tags:
    signature.delete_tag(tag.name)

signature.add_tag('EXAMPLE')

try:
    signature.commit()
except RuntimeError as e:
    print('Error: {0}'.format(e))
    sys.exit(1)

```

### Code Highlights

Snippet                                   | Description                                                                       |
----------------------------------------- | --------------------------------------------------------------------------------- |
`tc = ThreatConnect(api_access_id,...`    | Instantiate the ThreatConnect object. |
`signatures = tc.signatures()`          | Instantiate an Signatures container object. |
`signature = signatures.add('Updated...` | Add a resource object setting the name and owner. |
`signature.set_id('20')`                  | Set the ID of the Signature to the **EXISTING** signature ID to update. |
`signature.load_attributes()`             | Load existing attributes into the Signature object. |
`signature.delete_attribute(attribute.id)`| Add delete flag on the attribute with type 'Description'. |
`signature.add_attribute('Description...` | Add an Attribute of type 'Description' to the Resource. |
`signature.load_tags()`                   | Load existing tags into the Signature object. |
`signature.delete_tag(tag.name)`          | Add delete flag on to all Tags. |
`signature.add_tag('EXAMPLE')`            | Add a Tag to the Resource. |
`signature.commit()`                      | Trigger multiple API calls to update/delete Resource, Attributes, and Tags. |

## Delete an Signature Resource

```python
...

tc = ThreatConnect(api_access_id, api_secret_key, api_default_org, api_base_url)

signatures = tc.signatures()

signature = signatures.add('', owner)
signature.set_id(dl_id)

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
`signatures = tc.signatures()`          | Instantiate an Signatures container object. |
`signature = signatures.add('Updated...` | Add a resource object setting the name and owner. |
`signature.set_id('20')`                  | Set the ID of the Signature to the **EXISTING** signature ID to delete. |
`signature.delete()`                      | Trigger API calls to delete Resource. |
