# Emails Commit
Working with ThreatConnect Email Resources.

## Add an Email Resource

```python
...

tc = ThreatConnect(api_access_id, api_secret_key, api_default_org, api_base_url)

emails = tc.emails()
    
owner = 'Example Community'
email = emails.add('New Email', owner)
email.add_attribute('Description', 'Description Example')
email.add_tag('EXAMPLE')
email.set_security_label('TLP Green')
try:
    email.commit()
except RuntimeError as e:
    print('Error: {0}'.format(e))
    sys.exit(1)
```

### Code Highlights

Snippet                                   | Description                                                                       |
----------------------------------------- | --------------------------------------------------------------------------------- |
`tc = ThreatConnect(api_access_id,...`    | Instantiate the ThreatConnect object. |
`emails = tc.emails()`          | Instantiate an Emails container object. |
`email = emails.add('New Ads...` | Add a resource object setting the name and owner. |
`email.add_attribute('Description...` | Add an Attribute of type 'Description' to the Resource. |
`email.add_tag('EXAMPLE')`            | Add a Tag to the Resource. |
`email.set_security_label('TLPGre...` | Add a Security Label to the Resource. |
`email.commit()`                      | Trigger multiple API calls to write Resource, Attributes, Security Labels, and Tags. |

## Update an Email Resource

```python
...

tc = ThreatConnect(api_access_id, api_secret_key, api_default_org, api_base_url)

emails = tc.emails()

owner = 'Example Community'
email = emails.add('Updated Email', owner)
email.set_id('20')

email.load_attributes()
for attribute in email.attributes:
    if attribute.type == 'Description':
        email.delete_attribute(attribute.id)

email.add_attribute('Description', 'Updated Description')

email.load_tags()
for tag in email.tags:
    email.delete_tag(tag.name)

email.add_tag('EXAMPLE')

try:
    email.commit()
except RuntimeError as e:
    print('Error: {0}'.format(e))
    sys.exit(1)

```

### Code Highlights

Snippet                                   | Description                                                                       |
----------------------------------------- | --------------------------------------------------------------------------------- |
`tc = ThreatConnect(api_access_id,...`    | Instantiate the ThreatConnect object. |
`emails = tc.emails()`          | Instantiate an Emails container object. |
`email = emails.add('Updated...` | Add a resource object setting the name and owner. |
`email.set_id('20')`                  | Set the ID of the Email to the **EXISTING** email ID to update. |
`email.load_attributes()`             | Load existing attributes into the Email object. |
`email.delete_attribute(attribute.id)`| Add delete flag on the attribute with type 'Description'. |
`email.add_attribute('Description...` | Add an Attribute of type 'Description' to the Resource. |
`email.load_tags()`                   | Load existing tags into the Email object. |
`email.delete_tag(tag.name)`          | Add delete flag on to all Tags. |
`email.add_tag('EXAMPLE')`            | Add a Tag to the Resource. |
`email.commit()`                      | Trigger multiple API calls to update/delete Resource, Attributes, and Tags. |

## Delete an Email Resource

```python
...

tc = ThreatConnect(api_access_id, api_secret_key, api_default_org, api_base_url)

emails = tc.emails()

email = emails.add('', owner)
email.set_id(dl_id)

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
`emails = tc.emails()`          | Instantiate an Emails container object. |
`email = emails.add('Updated...` | Add a resource object setting the name and owner. |
`email.set_id('20')`                  | Set the ID of the Email to the **EXISTING** email ID to delete. |
`email.delete()`                      | Trigger API calls to delete Resource. |
