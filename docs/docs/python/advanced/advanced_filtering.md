# Advanced Filtering
The Python SDK provides a powerful filtering system.  When possible it allows the user to set API filters that limit the results returned from the API.  If further filtering is required there are Post Filters that allow the user to further refine the result set.  The API filters in a single Filter Object will **OR** the results together, while the Post Filter will **AND** the results.

## Print Filter Object
After creating a Filter Object the Object can be printed which will display the number of Request Objects created as well as the supported API Filters and Post Filters.  A list of filters can also be retrieved by using the `filter1.filters` property.
```python
... 

try:
    filter1 = adversary.add_filter()
    filter1.add_owner(owners)
    filter1.add_tag('APT')
except AttributeError as e:
    print('Error: {0}'.format(e))
    sys.exit(1)`

    print(filter1)
```

### Resulting Output

```text
_________________________________Filter Object__________________________________
Filter Properties                       
  Operator                     FilterSetOperator.AND                             
  Request Objects              1                                                 

Owners                                  
  Owner                        Example Community                                 

Filters                                 
  Filter                       api filter by tag "APT"                           

API Filters                             
  Filter                       add_adversary_id                                  
  Filter                       add_email_id                                      
  Filter                       add_document_id                                   
  Filter                       add_id                                            
  Filter                       add_incident_id                                   
  Filter                       add_indicator                                     
  Filter                       add_security_label                                
  Filter                       add_signature_id                                  
  Filter                       add_threat_id                                     
  Filter                       add_tag                                           
  Filter                       add_victim_id                                     

Post Filters                            
  Filter                       add_pf_name                                       
  Filter                       add_pf_date_added                                 
```

## Filter Object Basics
As mentioned above an API Filters will join the results.  In the example below the API results will contain any Adversary that has an association with the Indicator *10.20.30.40* OR an association with the Victim with an ID of 10 OR has the tag of *APT*.

```python
filter1 = adversary.add_filter()
filter1 = adversary.indicator('10.20.30.40')
filter1 = adversary.victim_id(10)
filter1 = adversary.tag('APT')
```

As mentioned above the Post Filters will intersect the results.  In the example below the API results will only contain Adversaries that have the name **"Bad Guy"** and have a date added >= **2015-06-18T20:21:45-05:00**.

```python
filter1 = adversary.add_filter()
filter1 = adversary.add_pf_name('Bad Guy')
filter1 = adversary.add_pf_date_added('2015-06-18T20:21:45-05:00', FilterOperator.GE)
```

## Indicator Modified Since API Filter
The **Modified Since** filter applies to the Indicators Container, but can only be used by on **base** indicator search (e.g /v2/indicators).  If a filter on modified since is required an a different indicator search there is a Post Filter for modified since that works on all Indicator result sets. 

```python
...

modified_since = (datetime.isoformat(datetime(2015, 6, 17))) + 'Z'
indicators.set_modified_since(modified_since)
```

## Multiple Filter Objects
The Python SDK support adding multiple Filter Object to a Resource Container.  A **filter_operator** allows a user to configure the results sets of the separate Filter Objects to be **JOINED** or **INTERSECTED**.  No **filter_operator** is required on the first Filter Object added and each subsequent Filter Object and be joined or intersected.

```python
# filter results
try:
    filter1 = indicators.add_filter()
    filter1.add_owner(owners)
    filter1.add_security_label('TLP Red')
except AttributeError as e:
    print(e)
    sys.exit(1)

# filter results
try:
    filter2 = indicators.add_filter()
    filter2.add_owner(owners)
    filter2.add_filter_operator(FilterSetOperator.AND)
    filter2.add_threat_id(38)
except AttributeError as e:
    print(e)
    sys.exit(1)

# filter results
try:
    filter3 = indicators.add_filter(IndicatorType.ADDRESSES)
    filter3.add_owner(owners)
    filter3.add_filter_operator(FilterSetOperator.OR)
    filter3.add_tag('EXAMPLE')
except AttributeError as e:
    print(e)
    sys.exit(1)
```