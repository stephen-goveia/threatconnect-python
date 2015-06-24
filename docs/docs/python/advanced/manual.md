# Manual API Calls
The Python SDK supports a more manual way to access the API by allowing the creation of a RequestObject and submitting to the `api_request()` method.  The result returned with be a *Python Requests* object containing the HTTP Status Code, Response Headers and API Results.


## Indicator Retrieval
The Example below shows how to create a RequestObject that will retrieve all Indicators from a specified Owner.

```python
...

tc = ThreatConnect(api_access_id, api_secret_key, api_default_org, api_base_url)

ro = RequestObject()
ro.set_http_method('GET')
ro.set_owner('Example Community')
ro.set_owner_allowed(True)
ro.set_resource_pagination(True)
ro.set_request_uri('/v2/indicators')

results = tc.api_request(ro)
if results.headers['content-type'] == 'application/json':
    data = results.json()
    print(json.dumps(data, indent=4))
```

### Code Highlights
Refer the the ThreatConnect API documentation for proper values for the RequestObject.

Snippet                                   | Description                                                                       |
----------------------------------------- | --------------------------------------------------------------------------------- |
`ro = RequestObject()`                    | Instantiate and instance of a Request Object. |
`ro.set_http_method('GET')`               | Set the HTTP Method for the request. |
`ro.set_owner('Example Community')`       | Set the Owner for the request (optional). |
`ro.set_owner_allowed(True)`              | Set the Owner Allowed flag for the request to indicate if this API call supports owners. |
`ro.set_resource_pagination(True)`        | Set the Pagination flag for the request to indicate if this API call supports pagination. |
`ro.set_request_uri('/v2/indicators')`    | Set the URI for the request. |
`results = tc.api_request(ro)`            | Trigger the API request and store result as *results*. |

## Document Contents Download
The Example below shows how to create a RequestObject that will retrieve the contents of a Document stored in a Document Resource.

```python
...

tc = ThreatConnect(api_access_id, api_secret_key, api_default_org, api_base_url)

ro = RequestObject()
ro.set_http_method('GET')
ro.set_owner('Example Community')
ro.set_owner_allowed(True)
ro.set_resource_pagination(False)
ro.set_request_uri('/v2/groups/documents/19/download')

results = tc.api_request(ro)
if results.headers['content-type'] == 'application/octet-stream':
    file_contents = results.content
    print(file_contents)
```

### Code Highlights
Refer the the ThreatConnect API documentation for proper values for the RequestObject.

Snippet                                   | Description                                                                       |
----------------------------------------- | --------------------------------------------------------------------------------- |
`ro = RequestObject()`                    | Instantiate and instance of a Request Object. |
`ro.set_http_method('GET')`               | Set the HTTP Method for the request. |
`ro.set_owner('Example Community')`       | Set the Owner for the request (optional). |
`ro.set_owner_allowed(True)`              | Set the Owner Allowed flag for the request to indicate if this API call supports owners. |
`ro.set_resource_pagination(True)`        | Set the Pagination flag for the request to indicate if this API call supports pagination. |
`ro.set_request_uri('/v2/indicators')`    | Set the URI for the request. |
`results = tc.api_request(ro)`            | Trigger the API request and store result as *results*. |

## Document Creation and Upload
The Example below shows how to create a RequestObject that will creat a Document Resource in ThreatConnect and upload a file to this Resource.

```python
...

tc = ThreatConnect(api_access_id, api_secret_key, api_default_org, api_base_url)

ro = RequestObject()
ro.set_http_method('POST')
body = {'name': 'Raw Upload Example', 'fileName': 'raw_example.txt'}
ro.set_body(json.dumps(body))
ro.set_content_type('application/json')
ro.set_owner('Example Community')
ro.set_owner_allowed(True)
ro.set_resource_pagination(False)
ro.set_request_uri('/v2/groups/documents')

print(ro)

results = tc.api_request(ro)
if results.headers['content-type'] == 'application/json':
    data = results.json()
    print(json.dumps(data, indent=4))

    document_id = data['data']['document']['id']

    ro = RequestObject()
    ro.set_http_method('POST')
    body = 'Raw upload example file Contents.'
    ro.set_body(body)
    ro.set_content_type('application/octet-stream')
    ro.set_owner('Example Community')
    ro.set_owner_allowed(True)
    ro.set_resource_pagination(False)
    ro.set_request_uri('/v2/groups/documents/{0}/upload'.format(document_id))

    results = tc.api_request(ro)
    print('Status Code: {0}'.format(results.status_code))
```

### Code Highlights
Refer the the ThreatConnect API documentation for proper values for the RequestObject.

Snippet                                   | Description                                                                       |
----------------------------------------- | --------------------------------------------------------------------------------- |
`ro = RequestObject()`                    | Instantiate and instance of a Request Object. |
`body = {'name': 'Raw Upload Exam...`     | Create the JSON body for POST. |
`ro.set_http_method('POST')`              | Set the HTTP Method for the request. |
`ro.set_owner('Example Community')`       | Set the Owner for the request (optional). |
`ro.set_owner_allowed(True)`              | Set the Owner Allowed flag for the request to indicate if this API call supports owners. |
`ro.set_resource_pagination(False)`       | Set the Pagination flag for the request to indicate if this API call supports pagination. |
`ro.set_request_uri('/v2/groups/doc...`   | Set the URI for the request. |
`print(ro)`                               | Optionally display the Request Object before submitting. |
`results = tc.api_request(ro)`            | Trigger the API request and store result as *results*. |
`document_id = data['data']['doc...`      | Get the ID of the created Document to use in the contents upload. |
