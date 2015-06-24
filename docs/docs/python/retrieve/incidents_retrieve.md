# Incidents Retrieve
Working with ThreatConnect Incident Resources.

## Supported API Filters
API filters use the API filtering feature to limit the result set returned from the API.

Filter               | Value Type   | Description                                                  |
---------------------| ------------ | ------------------------------------------------------------ |  
add_document_id()    | int          | Filter Incident on associated Document ID. |
add_email_id()       | int          | Filter Incident on associated Email ID. |
add_incident_id()    | int          | Filter Incident on associated Incident ID. |
add_indicator()      | int          | Filter Incident on associated Indicator. |
add_owner()          | list or str  | Filter Incident on associated Owner. |
add_security_label() | str          | Filter Incident on associated Security Label. |
add_signature_id()   | int          | Filter Incident on associated Signature ID. |
add_tag()            | str          | Filter Incident on applied Tag. |
add_threat_id()      | int          | Filter Incident on associated Threat ID. |
add_victim_id()      | int          | Filter Incident on associated Victim ID. |

## Supported Post Filters
Post filters are applied on the results returned by the API request.

Filter               | Value Type   | Description                                                  |
---------------------| ------------ | ------------------------------------------------------------ | 
add_pf_name()        | str          | Filter Incident on name. |
add_pf_date_added()  | str          | Filter Incident on date added. |

## Filter Example

This example will demonstrate how to retrieve incidents while applying filters.  In this example two filters will be added, one for the owner and another for a tag.  The result set returned from this example would contain any Incidents in the "Example Community" Owner that has a Tag of EXAMPLE.

> The import statement and reading of the configuration files have been replace with `...` for brevity.
<br/>

```python
...

tc = ThreatConnect(api_access_id, api_secret_key, api_default_org, api_base_url)

incidents = tc.incidents()

try:
    filter1 = incidents.add_filter()
    filter1.add_owner(owners)
    filter1.add_tag('APT')
except AttributeError as e:
    print('Error: {0}'.format(e))
    sys.exit(1)

try:
    incidents.retrieve()
except RuntimeError as e:
    print('Error: {0}'.format(e))

for incident in incidents:
    print(incident.id)
    print(incident.name)
    print(incident.date_added)
    print(incident.weblink)
        
    # incident specific property
    print(g_associations.event_date)
```

> Note: The `filter1` object contains a `filters` property which provides a list of supported filters for the resource type being retrieved. To display this list `print(filter1.filters)` can be used.  For more on using Filters see the Advanced Filter Tutorial.

### Code Highlights

Snippet                                   | Description                                                                       |
----------------------------------------- | --------------------------------------------------------------------------------- |
`tc = ThreatConnect(api_access_id,...`    | Instantiate the ThreatConnect object. |
`incidents = tc.incidents()`              | Instantiate an Incidents container object. |
`filter1 = indicator_add_filter(...`      | Add a filter object to the Incidents container object (support multiple filter objects). |
`filter1.add_tag('EXAMPLE')`              | Add API filter to be applied to the API request. |
`incidents.retrieve()`                    | Trigger the API request and retrieve the incidents intelligence data. |
`for incident in incidents:`              | Iterate over the Incidents container object generator. |
`print(incident.id)`                      | Display the 'id' property of the Incident object. |

## Loading Attributes Example
The example below continues from the previous 'Filter Example'.  Iterating through the 'incidents' container provides `incident` objects.  By calling the `load_attribute()` method of the incident object an API request is triggered and the resulting data is stored as attribute objects in the parent incident object.  These attribute object can be retrieve by iterating over the `attributes` property, which will return the individual attribute objects.

```python
 ...

    incident.load_attributes()
    for attribute in incident.attributes:
        print(attribute.type)
        print(attribute.value)
        print(attribute.date_added)
        print(attribute.last_modified)
        print(attribute.displayed)
```

### Code Highlights

Snippet                                   | Description                                                                       |
----------------------------------------- | --------------------------------------------------------------------------------- |
`incident.load_attributes()`              | Trigger API call to load attributes into the Incident Object. |
`for attribute in incident.attributes:`   | Iterate over the Attribute property object generator. |
`print(attribute.type)`                   | Display the 'type' property of the Attribute object. |

## Loading Security Label Example
The example below continues from the previous 'Loading Attributes Example'.  While still in the incidents loop the Incident Security Label can be loaded by calling the `load_security_label()` method of the Incident object.  By calling this method another API request will be triggered and the resulting data will be stored as a security label object in the Incident Object.  This object can be then directly access from the `security_label` property.

```python
 ...

    incident.load_security_label()
    if incident.security_label is not None:
        print(incident.security_label.name))
        print(incident.security_label.description))
        print(incident.security_label.date_added))
```

### Code Highlights

Snippet                                   | Description                                                                       |
----------------------------------------- | --------------------------------------------------------------------------------- |
`incident.load_security_label()`          | Trigger API call to load the security label into the Incident Object. |
`if incident.security_label is not ...`   | Ensure the object has been loaded before displaying properties. |
`print(incident.security_label.name)`     | Display the 'name' property of the Security Label object. |


## Loading Tags Example
The example below continues from the previous 'Loading Security Label Example'.  While still in the incidents loop the Incident Tags can be loaded by calling the `load_tags()` method of the Incident object.  By calling this method another API request will be triggered and the resulting data will be stored as a tag objects in the Incident Object.  This object can be then directly access from the `tags` property.

```python
...

    incident.load_tags()
    for tag in incident.tags:
        print(tag.name)
        print(tag.weblink)
```

### Code Highlights

Snippet                                   | Description                                                                       |
----------------------------------------- | --------------------------------------------------------------------------------- |
`incident.load_tags()`                    | Trigger API call to load tags into the Adverary Object. |
`for tag in incident.tags:`               | Iterate over the Attribute property object generator. |
`print(tag.name)`                         | Display the 'name' property of the Attribute object. |

## Group Associations
Iterate through all Groups associated with this Incident.  These group are pulled directly from the API and are not stored in the Incident object.

```python
...

    for g_associations in incident.group_associations:
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
`for g_associations in incident.grou...`  | Trigger API call to retrieve all Groups associated with this incident. |
`print(g_association.id)`                 | Display the 'id' property of the associated Group object. |


## Indicator Associations
Iterate through all Indicators associated with this Incident.  These group are pulled directly from the API and are not stored in the Incident object.

```python
...

    for i_associations in incident.indicator_associations:
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
`for i_associations in incident.ind_...`  | Trigger API call to retrieve all Indicators associated with this incident. |
`print(i_association.id)`                 | Display the 'id' property of the associated Indicator object. |

## Victim Associations
Iterate through all Victims associated with this Incident.  These group are pulled directly from the API and are not stored in the Incident object.

```python
...

    for v_associations in incident.victim_associations:
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
`for v_associations in indicator.vic_...` | Trigger API call to retrieve all Victims associated with this incident. |
`print(v_association.id)`                 | Display the 'id' property of the associated Victim object. |

## CSV Output
Display the Incident object parameters in a CSV format.  The *csv_header* property should only be called once per result set.

```python
...

    print(incident.csv_header)
    print(incident.csv)
```

### Code Highlights

Snippet                                   | Description                                                                       |
----------------------------------------- | --------------------------------------------------------------------------------- |
`print(incident.csv_header)`              | Display the Incident object properties CSV column headers. |
`print(incident.csv)`                     | Display the Incident object properties CSV row data. |

## JSON Output
Display the Incident object parameters in a JSON format.

```python
...

    print(incident.json)
```
        
## KeyVal Output
Display the Incident object parameters in a Key Value format.

```python
...

    print(incident.keyval)
```
