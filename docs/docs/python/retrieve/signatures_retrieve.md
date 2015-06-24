# Signatures Retrieve
Working with ThreatConnect Signature Resources.

## Supported API Filters
API filters use the API filtering feature to limit the result set returned from the API.

Filter               | Value Type   | Description                                                  |
---------------------| ------------ | ------------------------------------------------------------ |  
add_document_id()    | int          | Filter Signature on associated Document ID. |
add_email_id()       | int          | Filter Signature on associated Email ID. |
add_incident_id()    | int          | Filter Signature on associated Incident ID. |
add_indicator()      | int          | Filter Signature on associated Indicator. |
add_owner()          | list or str  | Filter Signature on associated Owner. |
add_security_label() | str          | Filter Signature on associated Security Label. |
add_signature_id()   | int          | Filter Signature on associated Signature ID. |
add_tag()            | str          | Filter Signature on applied Tag. |
add_threat_id()      | int          | Filter Signature on associated Threat ID. |
add_victim_id()      | int          | Filter Signature on associated Victim ID. |

## Supported Post Filters
Post filters are applied on the results returned by the API request.

Filter               | Value Type   | Description                                                  |
---------------------| ------------ | ------------------------------------------------------------ | 
add_pf_name()        | str          | Filter Signature on name. |
add_pf_date_added()  | str          | Filter Signature on date added. |

## Filter Example

This example will demonstrate how to retrieve signatures while applying filters.  In this example two filters will be added, one for the owner and another for a tag.  The result set returned from this example would contain any Signatures in the "Example Community" Owner that has a Tag of EXAMPLE.

> The import statement and reading of the configuration files have been replace with `...` for brevity.
<br/>

```python
...

tc = ThreatConnect(api_access_id, api_secret_key, api_default_org, api_base_url)

signatures = tc.signatures()

try:
    filter1 = signatures.add_filter()
    filter1.add_owner(owners)
    filter1.add_tag('APT')
except AttributeError as e:
    print('Error: {0}'.format(e))
    sys.exit(1)

try:
    signatures.retrieve()
except RuntimeError as e:
    print('Error: {0}'.format(e))

for signature in signatures:
    print(signature.id)
    print(signature.name)
    print(signature.date_added)
    print(signature.weblink)
```

> Note: The `filter1` object contains a `filters` property which provides a list of supported filters for the resource type being retrieved. To display this list `print(filter1.filters)` can be used.  For more on using Filters see the Advanced Filter Tutorial.

### Code Highlights

Snippet                                   | Description                                                                       |
----------------------------------------- | --------------------------------------------------------------------------------- |
`tc = ThreatConnect(api_access_id,...`    | Instantiate the ThreatConnect object. |
`signatures = tc.signatures()`            | Instantiate an Signatures container object. |
`filter1 = indicator_add_filter(...`      | Add a filter object to the Signatures container object (support multiple filter objects). |
`filter1.add_tag('EXAMPLE')`              | Add API filter to be applied to the API request. |
`signatures.retrieve()`                   | Trigger the API request and retrieve the signatures intelligence data. |
`for signature in signatures:`            | Iterate over the Signatures container object generator. |
`print(signature.id)`                     | Display the 'id' property of the Signature object. |

## Signature Download
Download the signature contents for the Signature resource.

```python
...

    signature.download()
    if signature.contents is not None:
        print(signature.contents)
```

### Code Highlights

Snippet                                   | Description                                                                       |
----------------------------------------- | --------------------------------------------------------------------------------- |
`signature.download()`                    | Trigger API request to download the Document contents. |
`if signature.contents is not None:`      | Validate the signature has downloaded before displaying. |
`print(signature.contents)`               | Display the contents of the signature. |

## Loading Attributes Example
The example below continues from the previous 'Filter Example'.  Iterating through the 'signatures' container provides `signature` objects.  By calling the `load_attribute()` method of the signature object an API request is triggered and the resulting data is stored as attribute objects in the parent signature object.  These attribute object can be retrieve by iterating over the `attributes` property, which will return the individual attribute objects.

```python
 ...

    signature.load_attributes()
    for attribute in signature.attributes:
        print(attribute.type)
        print(attribute.value)
        print(attribute.date_added)
        print(attribute.last_modified)
        print(attribute.displayed)
```

### Code Highlights

Snippet                                   | Description                                                                       |
----------------------------------------- | --------------------------------------------------------------------------------- |
`signature.load_attributes()`             | Trigger API call to load attributes into the Signature Object. |
`for attribute in signature.attributes:`  | Iterate over the Attribute property object generator. |
`print(attribute.type)`                   | Display the 'type' property of the Attribute object. |

## Loading Security Label Example
The example below continues from the previous 'Loading Attributes Example'.  While still in the signatures loop the Signature Security Label can be loaded by calling the `load_security_label()` method of the Signature object.  By calling this method another API request will be triggered and the resulting data will be stored as a security label object in the Signature Object.  This object can be then directly access from the `security_label` property.

```python
 ...

    signature.load_security_label()
    if signature.security_label is not None:
        print(signature.security_label.name))
        print(signature.security_label.description))
        print(signature.security_label.date_added))
```

### Code Highlights

Snippet                                   | Description                                                                       |
----------------------------------------- | --------------------------------------------------------------------------------- |
`signature.load_security_label()`         | Trigger API call to load the security label into the Signature Object. |
`if signature.security_label is not ...`  | Ensure the object has been loaded before displaying properties. |
`print(signature.security_label.name)`    | Display the 'name' property of the Security Label object. |


## Loading Tags Example
The example below continues from the previous 'Loading Security Label Example'.  While still in the signatures loop the Signature Tags can be loaded by calling the `load_tags()` method of the Signature object.  By calling this method another API request will be triggered and the resulting data will be stored as a tag objects in the Signature Object.  This object can be then directly access from the `tags` property.

```python
...

    signature.load_tags()
    for tag in signature.tags:
        print(tag.name)
        print(tag.weblink)
```

### Code Highlights

Snippet                                   | Description                                                                       |
----------------------------------------- | --------------------------------------------------------------------------------- |
`signature.load_tags()`                   | Trigger API call to load tags into the Adverary Object. |
`for tag in signature.tags:`              | Iterate over the Attribute property object generator. |
`print(tag.name)`                         | Display the 'name' property of the Attribute object. |

## Group Associations
Iterate through all Groups associated with this Signature.  These group are pulled directly from the API and are not stored in the Signature object.

```python
...

    for g_associations in signature.group_associations:
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
`for g_associations in signature.grou...` | Trigger API call to retrieve all Groups associated with this signature. |
`print(g_association.id)`                 | Display the 'id' property of the associated Group object. |


## Indicator Associations
Iterate through all Indicators associated with this Signature.  These group are pulled directly from the API and are not stored in the Signature object.

```python
...

    for i_associations in signature.indicator_associations:
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
`for i_associations in signature.ind_...` | Trigger API call to retrieve all Indicators associated with this signature. |
`print(i_association.id)`                 | Display the 'id' property of the associated Indicator object. |

## Victim Associations
Iterate through all Victims associated with this Signature.  These group are pulled directly from the API and are not stored in the Signature object.

```python
...

    for v_associations in signature.victim_associations:
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
`for v_associations in indicator.vic_...` | Trigger API call to retrieve all Victims associated with this signature. |
`print(v_association.id)`                 | Display the 'id' property of the associated Victim object. |

## CSV Output
Display the Signature object parameters in a CSV format.  The *csv_header* property should only be called once per result set.

```python
...

    print(signature.csv_header)
    print(signature.csv)
```

### Code Highlights

Snippet                                   | Description                                                                       |
----------------------------------------- | --------------------------------------------------------------------------------- |
`print(signature.csv_header)`             | Display the Signature object properties CSV column headers. |
`print(signature.csv)`                    | Display the Signature object properties CSV row data. |

## JSON Output
Display the Signature object parameters in a JSON format.

```python
...

    print(signature.json)
```
        
## KeyVal Output
Display the Signature object parameters in a Key Value format.

```python
...

    print(signature.keyval)
```
