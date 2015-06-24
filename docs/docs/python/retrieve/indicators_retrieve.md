# Indicators Retrieve
Working with ThreatConnect Indicator Resources.

## Supported API Filters
API filters use the API filtering feature to limit the result set returned from the API.

Filter               | Value Type   | Description                                                  |
---------------------| ------------ | ------------------------------------------------------------ |  
add_indicator_id()   | int          | Filter Indicator on associated Adversary ID. |
add_document_id()    | int          | Filter Indicator on associated Document ID. |
add_email_id()       | int          | Filter Indicator on associated Email ID. |
add_incident_id()    | int          | Filter Indicator on associated Incident ID. |
add_indicator()      | int          | Filter Indicator on associated Indicator. |
add_owner()          | list or str  | Filter Indicator on associated Owner. |
add_security_label() | str          | Filter Indicator on associated Security Label. |
add_signature_id()   | int          | Filter Indicator on associated Signature ID. |
add_tag()            | str          | Filter Indicator on applied Tag. |
add_threat_id()      | int          | Filter Indicator on associated Threat ID. |
add_victim_id()      | int          | Filter Indicator on associated Victim ID. |

## Supported Post Filters
Post filters are applied on the results returned by the API request.

Filter                             | Value Type   | Description                                                  |
---------------------------------- | ------------ | ------------------------------------------------------------ | 
add_pf_attribute()                 | str          | Filter Indicators on attribute type. |
add_pf_confidence()                | int          | Filter Indicators on confidence value. |
add_pf_date_added()                | str          | Filter Indicators on date added. |
add_pf_last_modified()             | str          | Filter Indicators on last modified date. |
add_pf_rating()                    | str          | Filter Indicators on rating. |
add_pf_tag()                       | str          | Filter Indicators on tag. |
add_pf_threat_assess_confidence()  | int          | Filter Indicators on threat assess confidence. |
add_pf_threat_assess_rating()      | str          | Filter Indicators on threat assess confidence. |
add_pf_type()                      | str          | Filter Indicators on indicator type. |

## Filter Example

This example will demonstrate how to retrieve indicators while applying filters.  In this example two filters will be added, one for the owner and another for a tag.  The result set returned from this example would contain any Indicators in the "Example Community" Owner that has a Tag of EXAMPLE.

> The import statement and reading of the configuration files have been replaced with `...` for brevity.
<br/>

```python
...
tc = ThreatConnect(api_access_id, api_secret_key, api_default_org, api_base_url)

# indicator object
indicators = tc.indicators()
 
# add API/Post filters
try:
    filter1 = indicators.add_filter()
    filter1.add_owner(owners)
    filter1.add_tag('EXAMPLE')
except AttributeError as e:
    print(e)
    sys.exit(1)

# retrieve indicators and apply filters
try:
    indicators.retrieve()
except RuntimeError as e:
    print(e)
    sys.exit(1)

# iterate through results
for indicator in indicators:
    if isinstance(indicator.indicator, dict):
        for indicator_type, indicator_value in indicator.indicator.items():
            print('{0}: {1}'.format(indicator_type, indicator_value))
    else:
        print(indicator.indicator)
    print(indicator.id)
    print(indicator.owner_name)
    print(indicator.date_added)
    print(indicator.rating)
    print(indicator.confidence)
    print(indicator.weblink)
    
```

> Note: The `filter1` object contains a `filters` property which provides a list of supported filters for the resource type being retrieved. To display this list `print(filter1.filters)` can be used.  For more on using Filters see the Advanced Filter Tutorial.

### Code Highlights

Snippet                                   | Description                                                                       |
----------------------------------------- | --------------------------------------------------------------------------------- |
`tc = ThreatConnect(api_access_id,...`    | Instantiate the ThreatConnect object. |
`indicators = tc.indicators()`            | Instantiate an Indicators container object. |
`filter1 = indicator_add_filter(...`      | Add a filter object to the Indicators container object (support multiple filter objects). |
`filter1.add_tag('EXAMPLE')`              | Add API filter to be applied to the API request. |
`indicator.retrieve()`                    | Trigger the API request and retrieve the indicators intelligence data. |
`for indicator in indicators:`            | Iterate over the Indicators container object generator. |
`print(indicator.indicator)`              | Display the 'indicator' property of the Indicator object. |

## Loading Attributes Example
The example below continues from the previous 'Filter Example'.  Iterating through the 'indicators' container provides `indicator` objects.  By calling the `load_attribute()` method of the indicator object an API request is triggered and the resulting data is stored as attribute objects in the parent indicator object.  These attribute object can be retrieve by iterating over the `attributes` property generator, which will return the individual attribute objects.

```python
...
 
    indicator.load_attributes()
    for attribute in indicator.attributes:
        print(attribute.type)
        print(attribute.value)
        print(attribute.date_added)
        print(attribute.last_modified)
        print(attribute.displayed)
```

### Code Highlights

Snippet                                   | Description                                                                       |
----------------------------------------- | --------------------------------------------------------------------------------- |
`indicator.load_attributes()`             | Trigger API call to load attributes into the Indicator Object. |
`for attribute in indicator.attributes:`  | Iterate over the Attribute property object generator. |
`print(attribute.type)`                   | Display the 'type' property of the Attribute object. |

## Loading Security Label Example
The example below continues from the previous 'Loading Attributes Example'.  While still in the indicators loop the Indicator Security Label can be loaded by calling the `load_security_label()` method of the Indicator object.  By calling this method another API request will be triggered and the resulting data will be stored as a security label object in the Indicator Object.  This object can be then directly access from the `security_label` property.

```python
...

    indicator.load_security_label()
    if indicator.security_label is not None:
        print(indicator.security_label.name))
        print(indicator.security_label.description))
        print(indicator.security_label.date_added))
```

### Code Highlights

Snippet                                   | Description                                                                       |
----------------------------------------- | --------------------------------------------------------------------------------- |
`indicator.load_security_label()`         | Trigger API call to load the security label into the Indicator Object. |
`if indicator.security_label is not ...`  | Ensure the object has been loaded before displaying properties. |
`print(indicator.security_label.name)`    | Display the 'name' property of the Security Label object. |

## Loading Tags Example
The example below continues from the previous 'Loading Security Label Example'.  While still in the indicators loop the Indicator Tags can be loaded by calling the `load_tags()` method of the Indicator object.  By calling this method another API request will be triggered and the resulting data will be stored as a Tag objects in the Indicator Object.  This object can be then directly access from the `tags` property.

```python
...

    indicator.load_tags()
    for tag in indicator.tags:
        print(tag.name)
        print(tag.weblink)
```

### Code Highlights

Snippet                                   | Description                                                                       |
----------------------------------------- | --------------------------------------------------------------------------------- |
`indicator.load_tags()`                   | Trigger API call to load tags into the Indicator Object. |
`for tag in indicator.tags:`              | Iterate over the Attribute property object generator. |
`print(tag.name)`                         | Display the 'name' property of the Attribute object. |

## Group Associations
Iterate through all Groups associated with this Indicator.  These groups are pulled directly from the API and are not stored in the Indicator object.

```python
...

    for g_association in indicator.group_associations:
        print(g_association.id)
        print(g_association.name)
        if hasattr(g_association, 'type'):
            print(g_association.type)
        print(g_association.owner_name)
        print(g_association.date_added)
        print(g_association.weblink)
```

### Code Highlights

Snippet                                   | Description                                                                       |
----------------------------------------- | --------------------------------------------------------------------------------- |
`for g_associations in indicator.grou...` | Trigger API call to retrieve all Groups associated with this indicator. |
`print(g_association.id)`                 | Display the 'id' property of the associated Group object. |

## Indicator Associations
Iterate through all Indicators associated with this Indicator.  These Indicators are pulled directly from the API and are not stored in the Indicator object.

```python
...

    for i_associations in indicator.indicator_associations:
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
`for i_associations in indicator.ind_...` | Trigger API call to retrieve all Indicators associated with this indicator. |
`print(i_association.id)`                 | Display the 'id' property of the associated Indicator object. |

## Victim Associations
Iterate through all Victims associated with this Indicator.  These group are pulled directly from the API and are not store in the Indicator object.

```python
...

    for v_associations in indicator.victim_associations:
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
`for v_associations in indicator.vic_...` | Trigger API call to retrieve all Victims associated with this indicator. |
`print(v_association.id)`                 | Display the 'id' property of the associated Victim object. |

## CSV Output
Display the Indicator object properties in CSV format.

```python
...

    print(indicator.csv_header)
    print(indicator.csv)
```

### Code Highlights

Snippet                                   | Description                                                                       |
----------------------------------------- | --------------------------------------------------------------------------------- |
`print(indicator.csv_header)`             | Display the Indicator object properties CSV column headers (should only be run once per result set).|
`print(indicator.csv)`                    | Display the Indicator object properties CSV row data.|
        
## JSON Output
Display the Indicator object parameters in a JSON format.

```python
...

    print(indicator.json)
```

## KeyVal Output
Display the Indicator object parameters in a Key Value format.

```python

    print(indicator.keyval)
```

