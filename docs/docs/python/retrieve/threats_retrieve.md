# Threats Retrieve
Working with ThreatConnect Threat Resources.

## Supported API Filters
API filters use the API filtering feature to limit the result set returned from the API.

Filter               | Value Type   | Description                                                  |
---------------------| ------------ | ------------------------------------------------------------ |  
add_document_id()    | int          | Filter Threat on associated Document ID. |
add_email_id()       | int          | Filter Threat on associated Email ID. |
add_incident_id()    | int          | Filter Threat on associated Incident ID. |
add_indicator()      | int          | Filter Threat on associated Indicator. |
add_owner()          | list or str  | Filter Threat on associated Owner. |
add_security_label() | str          | Filter Threat on associated Security Label. |
add_signature_id()   | int          | Filter Threat on associated Signature ID. |
add_tag()            | str          | Filter Threat on applied Tag. |
add_threat_id()      | int          | Filter Threat on associated Threat ID. |
add_victim_id()      | int          | Filter Threat on associated Victim ID. |

## Supported Post Filters
Post filters are applied on the results returned by the API request.

Filter               | Value Type   | Description                                                  |
---------------------| ------------ | ------------------------------------------------------------ | 
add_pf_name()        | str          | Filter Threat on name. |
add_pf_date_added()  | str          | Filter Threat on date added. |

## Filter Example

This example will demonstrate how to retrieve threats while applying filters.  In this example two filters will be added, one for the owner and another for a tag.  The result set returned from this example would contain any Threats in the "Example Community" Owner that has a Tag of EXAMPLE.

> The import statement and reading of the configuration files have been replace with `...` for brevity.
<br/>

```python
...

tc = ThreatConnect(api_access_id, api_secret_key, api_default_org, api_base_url)

threats = tc.threats()

try:
    filter1 = threats.add_filter()
    filter1.add_owner(owners)
    filter1.add_tag('APT')
except AttributeError as e:
    print('Error: {0}'.format(e))
    sys.exit(1)

try:
    threats.retrieve()
except RuntimeError as e:
    print('Error: {0}'.format(e))

for threat in threats:
    print(threat.id)
    print(threat.name)
    print(threat.date_added)
    print(threat.weblink)
```

> Note: The `filter1` object contains a `filters` property which provides a list of supported filters for the resource type being retrieved. To display this list `print(filter1.filters)` can be used.  For more on using Filters see the Advanced Filter Tutorial.

### Code Highlights

Snippet                                   | Description                                                                       |
----------------------------------------- | --------------------------------------------------------------------------------- |
`tc = ThreatConnect(api_access_id,...`    | Instantiate the ThreatConnect object. |
`threats = tc.threats()`                  | Instantiate an Threats container object. |
`filter1 = indicator_add_filter(...`      | Add a filter object to the Threats container object (support multiple filter objects). |
`filter1.add_tag('EXAMPLE')`              | Add API filter to be applied to the API request. |
`threats.retrieve()`                      | Trigger the API request and retrieve the threats intelligence data. |
`for threat in threats:`                  | Iterate over the Threats container object generator. |
`print(threat.id)`                        | Display the 'id' property of the Threat object. |

## Loading Attributes Example
The example below continues from the previous 'Filter Example'.  Iterating through the 'threats' container provides `threat` objects.  By calling the `load_attribute()` method of the threat object an API request is triggered and the resulting data is stored as attribute objects in the parent threat object.  These attribute object can be retrieve by iterating over the `attributes` property, which will return the individual attribute objects.

```python
 ...

    threat.load_attributes()
    for attribute in threat.attributes:
        print(attribute.type)
        print(attribute.value)
        print(attribute.date_added)
        print(attribute.last_modified)
        print(attribute.displayed)
```

### Code Highlights

Snippet                                   | Description                                                                       |
----------------------------------------- | --------------------------------------------------------------------------------- |
`threat.load_attributes()`                | Trigger API call to load attributes into the Threat Object. |
`for attribute in threat.attributes:`     | Iterate over the Attribute property object generator. |
`print(attribute.type)`                   | Display the 'type' property of the Attribute object. |

## Loading Security Label Example
The example below continues from the previous 'Loading Attributes Example'.  While still in the threats loop the Threat Security Label can be loaded by calling the `load_security_label()` method of the Threat object.  By calling this method another API request will be triggered and the resulting data will be stored as a security label object in the Threat Object.  This object can be then directly access from the `security_label` property.

```python
 ...

    threat.load_security_label()
    if threat.security_label is not None:
        print(threat.security_label.name))
        print(threat.security_label.description))
        print(threat.security_label.date_added))
```

### Code Highlights

Snippet                                   | Description                                                                       |
----------------------------------------- | --------------------------------------------------------------------------------- |
`threat.load_security_label()`            | Trigger API call to load the security label into the Threat Object. |
`if threat.security_label is not ...`     | Ensure the object has been loaded before displaying properties. |
`print(threat.security_label.name)`       | Display the 'name' property of the Security Label object. |


## Loading Tags Example
The example below continues from the previous 'Loading Security Label Example'.  While still in the threats loop the Threat Tags can be loaded by calling the `load_tags()` method of the Threat object.  By calling this method another API request will be triggered and the resulting data will be stored as a tag objects in the Threat Object.  This object can be then directly access from the `tags` property.

```python
...

    threat.load_tags()
    for tag in threat.tags:
        print(tag.name)
        print(tag.weblink)
```

### Code Highlights

Snippet                                   | Description                                                                       |
----------------------------------------- | --------------------------------------------------------------------------------- |
`threat.load_tags()`                      | Trigger API call to load tags into the Adverary Object. |
`for tag in threat.tags:`                 | Iterate over the Attribute property object generator. |
`print(tag.name)`                         | Display the 'name' property of the Attribute object. |

## Group Associations
Iterate through all Groups associated with this Threat.  These group are pulled directly from the API and are not stored in the Threat object.

```python
...

    for g_associations in threat.group_associations:
        print(g_associations.id)
        print(g_associations.name)
        if hasattr(g_associations, 'type'):
            print(g_associations.type)
        print(g_associations.owner_name)
        print(g_associations.date_added)
        print(g_associations.weblink)
```

### Code Highlights

Snippet                                   | Description                                                                       |
----------------------------------------- | --------------------------------------------------------------------------------- |
`for g_associations in threat.grou...`    | Trigger API call to retrieve all Groups associated with this threat. |
`print(g_association.id)`                 | Display the 'id' property of the associated Group object. |


## Indicator Associations
Iterate through all Indicators associated with this Threat.  These group are pulled directly from the API and are not stored in the Threat object.

```python
...

    for i_associations in threat.indicator_associations:
        print(i_associations.id)
        print(i_associations.indicator)
        print(i_associations.type)
        print(i_associations.description)
        print(i_associations.owner_name)
        print(i_associations.rating)
        print(i_associations.confidence)
        print(i_associations.date_added)
        print(i_associations.last_modified)
        print(i_associations.weblink)
```

### Code Highlights

Snippet                                   | Description                                                                       |
----------------------------------------- | --------------------------------------------------------------------------------- |
`for i_associations in threat.ind_...`    | Trigger API call to retrieve all Indicators associated with this threat. |
`print(i_association.id)`                 | Display the 'id' property of the associated Indicator object. |

## Victim Associations
Iterate through all Victims associated with this Threat.  These group are pulled directly from the API and are not stored in the Threat object.

```python
...

    for v_associations in threat.victim_associations:
        print(v_associations.id)
        print(v_associations.name)
        print(v_associations.description)
        print(v_associations.owner_name)
        print(v_associations.nationality)
        print(v_associations.org)
        print(v_associations.suborg)
        print(v_associations.work_location)
        print(v_associations.weblink)
```

### Code Highlights

Snippet                                   | Description                                                                       |
----------------------------------------- | --------------------------------------------------------------------------------- |
`for v_associations in indicator.vic_...` | Trigger API call to retrieve all Victims associated with this threat. |
`print(v_association.id)`                 | Display the 'id' property of the associated Victim object. |

## CSV Output
Display the Threat object parameters in a CSV format.  The *csv_header* property should only be called once per result set.

```python
...

    print(threat.csv_header)
    print(threat.csv)
```

### Code Highlights

Snippet                                   | Description                                                                       |
----------------------------------------- | --------------------------------------------------------------------------------- |
`print(threat.csv_header)`                | Display the Threat object properties CSV column headers. |
`print(threat.csv)`                       | Display the Threat object properties CSV row data. |

## JSON Output
Display the Threat object parameters in a JSON format.

```python
...

    print(threat.json)
```
        
## KeyVal Output
Display the Threat object parameters in a Key Value format.

```python
...

    print(threat.keyval)
```
