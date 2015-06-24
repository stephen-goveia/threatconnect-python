# Threats Commit
Working with ThreatConnect Threat Resources.

## Add an Threat Resource

```python
...

tc = ThreatConnect(api_access_id, api_secret_key, api_default_org, api_base_url)

threats = tc.threats()
    
owner = 'Example Community'
threat = threats.add('New Threat', owner)
threat.add_attribute('Description', 'Description Example')
threat.add_tag('EXAMPLE')
threat.set_security_label('TLP Green')
try:
    threat.commit()
except RuntimeError as e:
    print('Error: {0}'.format(e))
    sys.exit(1)
```

### Code Highlights

Snippet                                   | Description                                                                       |
----------------------------------------- | --------------------------------------------------------------------------------- |
`tc = ThreatConnect(api_access_id,...`    | Instantiate the ThreatConnect object. |
`threats = tc.threats()`                  | Instantiate an Threats container object. |
`threat = threats.add('New Ads...`        | Add a resource object setting the name and owner. |
`threat.add_attribute('Description...`    | Add an Attribute of type 'Description' to the Resource. |
`threat.add_tag('EXAMPLE')`               | Add a Tag to the Resource. |
`threat.set_security_label('TLPGre...`    | Add a Security Label to the Resource. |
`threat.commit()`                         | Trigger multiple API calls to write Resource, Attributes, Security Labels, and Tags. |

## Update an Threat Resource

```python
...

tc = ThreatConnect(api_access_id, api_secret_key, api_default_org, api_base_url)

threats = tc.threats()

owner = 'Example Community'
threat = threats.add('Updated Threat', owner)
threat.set_id('20')

threat.load_attributes()
for attribute in threat.attributes:
    if attribute.type == 'Description':
        threat.delete_attribute(attribute.id)

threat.add_attribute('Description', 'Updated Description')

threat.load_tags()
for tag in threat.tags:
    threat.delete_tag(tag.name)

threat.add_tag('EXAMPLE')

try:
    threat.commit()
except RuntimeError as e:
    print('Error: {0}'.format(e))
    sys.exit(1)

```

### Code Highlights

Snippet                                   | Description                                                                       |
----------------------------------------- | --------------------------------------------------------------------------------- |
`tc = ThreatConnect(api_access_id,...`    | Instantiate the ThreatConnect object. |
`threats = tc.threats()`                  | Instantiate an Threats container object. |
`threat = threats.add('Updated...`        | Add a resource object setting the name and owner. |
`threat.set_id('20')`                     | Set the ID of the Threat to the **EXISTING** threat ID to update. |
`threat.load_attributes()`                | Load existing attributes into the Threat object. |
`threat.delete_attribute(attribute.id)`   | Add delete flag on the attribute with type 'Description'. |
`threat.add_attribute('Description...`    | Add an Attribute of type 'Description' to the Resource. |
`threat.load_tags()`                      | Load existing tags into the Threat object. |
`threat.delete_tag(tag.name)`             | Add delete flag on to all Tags. |
`threat.add_tag('EXAMPLE')`               | Add a Tag to the Resource. |
`threat.commit()`                         | Trigger multiple API calls to update/delete Resource, Attributes, and Tags. |

## Delete an Threat Resource

```python
...

tc = ThreatConnect(api_access_id, api_secret_key, api_default_org, api_base_url)

threats = tc.threats()

threat = threats.add('', owner)
threat.set_id(dl_id)

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
`threats = tc.threats()`                  | Instantiate an Threats container object. |
`threat = threats.add('Updated...`        | Add a resource object setting the name and owner. |
`threat.set_id('20')`                     | Set the ID of the Threat to the **EXISTING** threat ID to delete. |
`threat.delete()`                         | Trigger API calls to delete Resource. |
