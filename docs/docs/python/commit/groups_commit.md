# Groups Commit
Working with ThreatConnect Group Resources.

## Add an Group Resource

```python
...

tc = ThreatConnect(api_access_id, api_secret_key, api_default_org, api_base_url)

groups = tc.groups()
    
owner = 'Example Community'
group = groups.add('New Group', owner)
group.add_attribute('Description', 'Description Example')
group.add_tag('EXAMPLE')
group.set_security_label('TLP Green')
try:
    group.commit()
except RuntimeError as e:
    print('Error: {0}'.format(e))
    sys.exit(1)
```

### Code Highlights

Snippet                                   | Description                                                                       |
----------------------------------------- | --------------------------------------------------------------------------------- |
`tc = ThreatConnect(api_access_id,...`    | Instantiate the ThreatConnect object. |
`groups = tc.groups()`          | Instantiate an Groups container object. |
`group = groups.add('New Ads...` | Add a resource object setting the name and owner. |
`group.add_attribute('Description...` | Add an Attribute of type 'Description' to the Resource. |
`group.add_tag('EXAMPLE')`            | Add a Tag to the Resource. |
`group.set_security_label('TLPGre...` | Add a Security Label to the Resource. |
`group.commit()`                      | Trigger multiple API calls to write Resource, Attributes, Security Labels, and Tags. |

## Update an Group Resource

```python
...

tc = ThreatConnect(api_access_id, api_secret_key, api_default_org, api_base_url)

groups = tc.groups()

owner = 'Example Community'
group = groups.add('Updated Group', owner)
group.set_id('20')

group.load_attributes()
for attribute in group.attributes:
    if attribute.type == 'Description':
        group.delete_attribute(attribute.id)

group.add_attribute('Description', 'Updated Description')

group.load_tags()
for tag in group.tags:
    group.delete_tag(tag.name)

group.add_tag('EXAMPLE')

try:
    group.commit()
except RuntimeError as e:
    print('Error: {0}'.format(e))
    sys.exit(1)

```

### Code Highlights

Snippet                                   | Description                                                                       |
----------------------------------------- | --------------------------------------------------------------------------------- |
`tc = ThreatConnect(api_access_id,...`    | Instantiate the ThreatConnect object. |
`groups = tc.groups()`          | Instantiate an Groups container object. |
`group = groups.add('Updated...` | Add a resource object setting the name and owner. |
`group.set_id('20')`                  | Set the ID of the Group to the **EXISTING** group ID to update. |
`group.load_attributes()`             | Load existing attributes into the Group object. |
`group.delete_attribute(attribute.id)`| Add delete flag on the attribute with type 'Description'. |
`group.add_attribute('Description...` | Add an Attribute of type 'Description' to the Resource. |
`group.load_tags()`                   | Load existing tags into the Group object. |
`group.delete_tag(tag.name)`          | Add delete flag on to all Tags. |
`group.add_tag('EXAMPLE')`            | Add a Tag to the Resource. |
`group.commit()`                      | Trigger multiple API calls to update/delete Resource, Attributes, and Tags. |

## Delete an Group Resource

```python
...

tc = ThreatConnect(api_access_id, api_secret_key, api_default_org, api_base_url)

groups = tc.groups()

group = groups.add('', owner)
group.set_id(dl_id)

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
`groups = tc.groups()`          | Instantiate an Groups container object. |
`group = groups.add('Updated...` | Add a resource object setting the name and owner. |
`group.set_id('20')`                  | Set the ID of the Group to the **EXISTING** group ID to delete. |
`group.delete()`                      | Trigger API calls to delete Resource. |
