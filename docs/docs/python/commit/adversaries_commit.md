# Adversaries Commit
Working with ThreatConnect Adversary Resources.

## Add an Adversary Resource

```python
...

tc = ThreatConnect(api_access_id, api_secret_key, api_default_org, api_base_url)

adversaries = tc.adversaries()
    
owner = 'Example Community'
adversary = adversaries.add('New Adversary', owner)
adversary.add_attribute('Description', 'Description Example')
adversary.add_tag('EXAMPLE')
adversary.set_security_label('TLP Green')
try:
    adversary.commit()
except RuntimeError as e:
    print('Error: {0}'.format(e))
    sys.exit(1)
```

### Code Highlights

Snippet                                   | Description                                                                       |
----------------------------------------- | --------------------------------------------------------------------------------- |
`tc = ThreatConnect(api_access_id,...`    | Instantiate the ThreatConnect object. |
`adversaries = tc.adversaries()`          | Instantiate an Adversaries container object. |
`adversary = adversaries.add('New Ads...` | Add a resource object setting the name and owner. |
`adversary.add_attribute('Description...` | Add an Attribute of type 'Description' to the Resource. |
`adversary.add_tag('EXAMPLE')`            | Add a Tag to the Resource. |
`adversary.set_security_label('TLPGre...` | Add a Security Label to the Resource. |
`adversary.commit()`                      | Trigger multiple API calls to write Resource, Attributes, Security Labels, and Tags. |

## Update an Adversary Resource

```python
...

tc = ThreatConnect(api_access_id, api_secret_key, api_default_org, api_base_url)

adversaries = tc.adversaries()

owner = 'Example Community'
adversary = adversaries.add('Updated Adversary', owner)
adversary.set_id('20')

adversary.load_attributes()
for attribute in adversary.attributes:
    if attribute.type == 'Description':
        adversary.delete_attribute(attribute.id)

adversary.add_attribute('Description', 'Updated Description')

adversary.load_tags()
for tag in adversary.tags:
    adversary.delete_tag(tag.name)

adversary.add_tag('EXAMPLE')

try:
    adversary.commit()
except RuntimeError as e:
    print('Error: {0}'.format(e))
    sys.exit(1)

```

### Code Highlights

Snippet                                   | Description                                                                       |
----------------------------------------- | --------------------------------------------------------------------------------- |
`tc = ThreatConnect(api_access_id,...`    | Instantiate the ThreatConnect object. |
`adversaries = tc.adversaries()`          | Instantiate an Adversaries container object. |
`adversary = adversaries.add('Updated...` | Add a resource object setting the name and owner. |
`adversary.set_id('20')`                  | Set the ID of the Adversary to the **EXISTING** adversary ID to update. |
`adversary.load_attributes()`             | Load existing attributes into the Adversary object. |
`adversary.delete_attribute(attribute.id)`| Add delete flag on the attribute with type 'Description'. |
`adversary.add_attribute('Description...` | Add an Attribute of type 'Description' to the Resource. |
`adversary.load_tags()`                   | Load existing tags into the Adversary object. |
`adversary.delete_tag(tag.name)`          | Add delete flag on to all Tags. |
`adversary.add_tag('EXAMPLE')`            | Add a Tag to the Resource. |
`adversary.commit()`                      | Trigger multiple API calls to update/delete Resource, Attributes, and Tags. |

## Delete an Adversary Resource

```python
...

tc = ThreatConnect(api_access_id, api_secret_key, api_default_org, api_base_url)

adversaries = tc.adversaries()

adversary = adversaries.add('', owner)
adversary.set_id(dl_id)

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
`adversaries = tc.adversaries()`          | Instantiate an Adversaries container object. |
`adversary = adversaries.add('Updated...` | Add a resource object setting the name and owner. |
`adversary.set_id('20')`                  | Set the ID of the Adversary to the **EXISTING** adversary ID to delete. |
`adversary.delete()`                      | Trigger API calls to delete Resource. |
