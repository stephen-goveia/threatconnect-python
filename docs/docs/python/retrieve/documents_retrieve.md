# Documents Retrieve
Working with ThreatConnect Document Resources.

## Supported API Filters
API filters use the API filtering feature to limit the result set returned from the API.

Filter               | Value Type   | Description                                                  |
---------------------| ------------ | ------------------------------------------------------------ |  
add_document_id()    | int          | Filter Document on associated Document ID. |
add_email_id()       | int          | Filter Document on associated Email ID. |
add_incident_id()    | int          | Filter Document on associated Incident ID. |
add_indicator()      | int          | Filter Document on associated Indicator. |
add_owner()          | list or str  | Filter Document on associated Owner. |
add_security_label() | str          | Filter Document on associated Security Label. |
add_signature_id()   | int          | Filter Document on associated Signature ID. |
add_tag()            | str          | Filter Document on applied Tag. |
add_threat_id()      | int          | Filter Document on associated Threat ID. |
add_victim_id()      | int          | Filter Document on associated Victim ID. |

## Supported Post Filters
Post filters are applied on the results returned by the API request.

Filter               | Value Type   | Description                                                  |
---------------------| ------------ | ------------------------------------------------------------ | 
add_pf_name()        | str          | Filter Document on name. |
add_pf_date_added()  | str          | Filter Document on date added. |

## Filter Example

This example will demonstrate how to retrieve documents while applying filters.  In this example two filters will be added, one for the owner and another for a tag.  The result set returned from this example would contain any Documents in the "Example Community" Owner that has a Tag of EXAMPLE.

> The import statement and reading of the configuration files have been replace with `...` for brevity.
<br/>

```python
...

tc = ThreatConnect(api_access_id, api_secret_key, api_default_org, api_base_url)

documents = tc.documents()

try:
    filter1 = documents.add_filter()
    filter1.add_owner(owners)
    filter1.add_tag('APT')
except AttributeError as e:
    print('Error: {0}'.format(e))
    sys.exit(1)

try:
    documents.retrieve()
except RuntimeError as e:
    print('Error: {0}'.format(e))

for document in documents:
    print(document.id)
    print(document.name)
    print(document.date_added)
    print(document.owner_name)
    print(document.weblink)
    
    # document specific property
    print(document.file_name)
```

> Note: The `filter1` object contains a `filters` property which provides a list of supported filters for the resource type being retrieved. To display this list `print(filter1.filters)` can be used.  For more on using Filters see the Advanced Filter Tutorial.

### Code Highlights

Snippet                                   | Description                                                                       |
----------------------------------------- | --------------------------------------------------------------------------------- |
`tc = ThreatConnect(api_access_id,...`    | Instantiate the ThreatConnect object. |
`documents = tc.documents()`              | Instantiate an Documents container object. |
`filter1 = indicator_add_filter(...`      | Add a filter object to the Documents container object (support multiple filter objects). |
`filter1.add_tag('EXAMPLE')`              | Add API filter to be applied to the API request. |
`documents.retrieve()`                    | Trigger the API request and retrieve the documents intelligence data. |
`for document in documents:`              | Iterate over the Documents container object generator. |
`print(document.id)`                      | Display the 'id' property of the Document object. |

## Download Document Contents

```python
...

    document.download()
    if document.contents is not None:
        print(document.contents)
```

### Code Highlights

Snippet                                   | Description                                                                       |
----------------------------------------- | --------------------------------------------------------------------------------- |
`document.download()`                     | Trigger API request to download the Document contents. |
`if document.contents is not None:`       | Validate the document has downloaded before displaying. |
`print(document.contents)`                | Display the contents of the document (this should only be done for ASCII contents). |

## Loading Attributes Example
The example below continues from the previous 'Filter Example'.  Iterating through the 'documents' container provides `document` objects.  By calling the `load_attribute()` method of the document object an API request is triggered and the resulting data is stored as attribute objects in the parent document object.  These attribute object can be retrieve by iterating over the `attributes` property, which will return the individual attribute objects.

```python
 ...

    document.load_attributes()
    for attribute in document.attributes:
        print(attribute.type)
        print(attribute.value)
        print(attribute.date_added)
        print(attribute.last_modified)
        print(attribute.displayed)
```

### Code Highlights

Snippet                                   | Description                                                                       |
----------------------------------------- | --------------------------------------------------------------------------------- |
`document.load_attributes()`              | Trigger API call to load attributes into the Document Object. |
`for attribute in document.attributes:`   | Iterate over the Attribute property object generator. |
`print(attribute.type)`                   | Display the 'type' property of the Attribute object. |

## Loading Security Label Example
The example below continues from the previous 'Loading Attributes Example'.  While still in the documents loop the Document Security Label can be loaded by calling the `load_security_label()` method of the Document object.  By calling this method another API request will be triggered and the resulting data will be stored as a security label object in the Document Object.  This object can be then directly access from the `security_label` property.

```python
 ...

    document.load_security_label()
    if document.security_label is not None:
        print(document.security_label.name))
        print(document.security_label.description))
        print(document.security_label.date_added))
```

### Code Highlights

Snippet                                   | Description                                                                       |
----------------------------------------- | --------------------------------------------------------------------------------- |
`document.load_security_label()`          | Trigger API call to load the security label into the Document Object. |
`if document.security_label is not ...`   | Ensure the object has been loaded before displaying properties. |
`print(document.security_label.name)`     | Display the 'name' property of the Security Label object. |


## Loading Tags Example
The example below continues from the previous 'Loading Security Label Example'.  While still in the documents loop the Document Tags can be loaded by calling the `load_tags()` method of the Document object.  By calling this method another API request will be triggered and the resulting data will be stored as a tag objects in the Document Object.  This object can be then directly access from the `tags` property.

```python
...

    document.load_tags()
    for tag in document.tags:
        print(tag.name)
        print(tag.weblink)
```

### Code Highlights

Snippet                                   | Description                                                                       |
----------------------------------------- | --------------------------------------------------------------------------------- |
`document.load_tags()`                    | Trigger API call to load tags into the Adverary Object. |
`for tag in document.tags:`               | Iterate over the Attribute property object generator. |
`print(tag.name)`                         | Display the 'name' property of the Attribute object. |

## Group Associations
Iterate through all Groups associated with this Document.  These group are pulled directly from the API and are not stored in the Document object.

```python
...

    for g_associations in document.group_associations:
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
`for g_associations in document.grou...`  | Trigger API call to retrieve all Groups associated with this document. |
`print(g_association.id)`                 | Display the 'id' property of the associated Group object. |


## Indicator Associations
Iterate through all Indicators associated with this Document.  These group are pulled directly from the API and are not stored in the Document object.

```python
...

    for i_associations in document.indicator_associations:
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
`for i_associations in document.ind_...`  | Trigger API call to retrieve all Indicators associated with this document. |
`print(i_association.id)`                 | Display the 'id' property of the associated Indicator object. |

## Victim Associations
Iterate through all Victims associated with this Document.  These group are pulled directly from the API and are not stored in the Document object.

```python
...

    for v_associations in document.victim_associations:
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
`for v_associations in indicator.vic_...` | Trigger API call to retrieve all Victims associated with this document. |
`print(v_association.id)`                 | Display the 'id' property of the associated Victim object. |

## CSV Output
Display the Document object parameters in a CSV format.  The *csv_header* property should only be called once per result set.

```python
...

    print(document.csv_header)
    print(document.csv)
```

### Code Highlights

Snippet                                   | Description                                                                       |
----------------------------------------- | --------------------------------------------------------------------------------- |
`print(document.csv_header)`              | Display the Document object properties CSV column headers. |
`print(document.csv)`                     | Display the Document object properties CSV row data. |

## JSON Output
Display the Document object parameters in a JSON format.

```python
...

    print(document.json)
```
        
## KeyVal Output
Display the Document object parameters in a Key Value format.

```python
...

    print(document.keyval)
```
