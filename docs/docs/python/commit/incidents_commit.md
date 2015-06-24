# Incidents Commit
Working with ThreatConnect Incident Resources.

## Add an Incident Resource

```python
...

tc = ThreatConnect(api_access_id, api_secret_key, api_default_org, api_base_url)

incidents = tc.incidents()
    
owner = 'Example Community'
incident = incidents.add('New Incident', owner)
incident.add_attribute('Description', 'Description Example')
incident.add_tag('EXAMPLE')
incident.set_security_label('TLP Green')
try:
    incident.commit()
except RuntimeError as e:
    print('Error: {0}'.format(e))
    sys.exit(1)
```

### Code Highlights

Snippet                                   | Description                                                                       |
----------------------------------------- | --------------------------------------------------------------------------------- |
`tc = ThreatConnect(api_access_id,...`    | Instantiate the ThreatConnect object. |
`incidents = tc.incidents()`          | Instantiate an Incidents container object. |
`incident = incidents.add('New Ads...` | Add a resource object setting the name and owner. |
`incident.add_attribute('Description...` | Add an Attribute of type 'Description' to the Resource. |
`incident.add_tag('EXAMPLE')`            | Add a Tag to the Resource. |
`incident.set_security_label('TLPGre...` | Add a Security Label to the Resource. |
`incident.commit()`                      | Trigger multiple API calls to write Resource, Attributes, Security Labels, and Tags. |

## Update an Incident Resource

```python
...

tc = ThreatConnect(api_access_id, api_secret_key, api_default_org, api_base_url)

incidents = tc.incidents()

owner = 'Example Community'
incident = incidents.add('Updated Incident', owner)
incident.set_id('20')

incident.load_attributes()
for attribute in incident.attributes:
    if attribute.type == 'Description':
        incident.delete_attribute(attribute.id)

incident.add_attribute('Description', 'Updated Description')

incident.load_tags()
for tag in incident.tags:
    incident.delete_tag(tag.name)

incident.add_tag('EXAMPLE')

try:
    incident.commit()
except RuntimeError as e:
    print('Error: {0}'.format(e))
    sys.exit(1)

```

### Code Highlights

Snippet                                   | Description                                                                       |
----------------------------------------- | --------------------------------------------------------------------------------- |
`tc = ThreatConnect(api_access_id,...`    | Instantiate the ThreatConnect object. |
`incidents = tc.incidents()`          | Instantiate an Incidents container object. |
`incident = incidents.add('Updated...` | Add a resource object setting the name and owner. |
`incident.set_id('20')`                  | Set the ID of the Incident to the **EXISTING** incident ID to update. |
`incident.load_attributes()`             | Load existing attributes into the Incident object. |
`incident.delete_attribute(attribute.id)`| Add delete flag on the attribute with type 'Description'. |
`incident.add_attribute('Description...` | Add an Attribute of type 'Description' to the Resource. |
`incident.load_tags()`                   | Load existing tags into the Incident object. |
`incident.delete_tag(tag.name)`          | Add delete flag on to all Tags. |
`incident.add_tag('EXAMPLE')`            | Add a Tag to the Resource. |
`incident.commit()`                      | Trigger multiple API calls to update/delete Resource, Attributes, and Tags. |

## Delete an Incident Resource

```python
...

tc = ThreatConnect(api_access_id, api_secret_key, api_default_org, api_base_url)

incidents = tc.incidents()

incident = incidents.add('', owner)
incident.set_id(dl_id)

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
`incidents = tc.incidents()`          | Instantiate an Incidents container object. |
`incident = incidents.add('Updated...` | Add a resource object setting the name and owner. |
`incident.set_id('20')`                  | Set the ID of the Incident to the **EXISTING** incident ID to delete. |
`incident.delete()`                      | Trigger API calls to delete Resource. |
