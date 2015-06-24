# Python SDK

## About This Document

This guide gets you started coding Python applications using the ThreatConnect&trade; API. The Python SDK offers coverage of all features in version 2.0 of the ThreatConnect&trade; API -- including the ability to write data to ThreatConnect. This document will provide an overview of the reference implementation of the ThreatConnect&trade; Python SDK. 

The goal of this Python SDK library is to provide a programmatic abstraction layer around the ThreatConnect&trade; API without losing functional coverage over the available API resources. This abstraction layer enables developers to focus on writing enterprise functionality without worrying about low-level RESTful calls and authentication management.

> This document is not a replacement for the official ThreatConnect&trade; API Documentation. This document serves as a companion to the official documentation for the REST ThreatConnect&trade; API. Read the official documentation to gain a further understanding of the functional aspects of using the ThreatConnect&trade; API.

* * * 
## How to Use This Document

This document will teach you how to create groups, indicators, associations, tags, security labels, and victims. Along with creating data elements, you will be able to create, update, delete, and request data from the API using Python. This document assumes the reader knows the Python Programming Language.

All code examples will be noted  in a separate box with a monospaced font and line numbers to facilitate explanation of code functionality. When a single line of code wraps, the rounded right arrow “↪” will highlight that the code is a continuation of the prior line (see between line 2 and 3 below). This is a code sample with line numbers and syntax highlighting.

```python
...

resources = tc.adversaries()

resource = resources.add('Test Adversary')
resource.add_attribute('Description', 'Adversary 
↪ Sample Description')
resource.add_tag('Sample Adversary')
try:
    resources.commit('Acme Corp')
except RuntimeError as e:
    print(e)
```
## Getting Started

To get started, you’ll need to have Python 2.7+ installed along with the ThreatConnect&trade; Python SDK. Typically Python comes pre-installed on Linux/MacOS/Unix systems so additional step to install Python are not required.  This section will also highlight basic configuration to connect to the ThreatConnect&trade; API. While an IDE will facilitate development of larger scale systems, it is not required to follow the examples in this document.

###ThreatConnect Python SDK Installation
```
unzip threatconnect-python.zip
cd threatconnect-python
python setup.py install
```

To use the ThreatConnect&trade; RESTful API, an API user must be provisioned. See the official ThreatConnect&trade; API documentation for details on how to create an API user as it is out of scope for this document.

The Python SDK will need to be configured with an Access ID and Secret Key.  One way to achieve this is to use the `ConfigParser` module which is part of the Python Standard Library.  Another option is to use `ArgParse` and pass the configuration items via CLI arguments.  For this example we will stick with using Configparser.

<br/>
Example of using ConfigParser to read API configuration values.
```python
# read configuration file
config = ConfigParser.RawConfigParser()
config.read('threatconnect.conf')

try:
    api_access_id = config.get('threatconnect', 'api_access_id')
    api_secret_key = config.get('threatconnect', 'api_secret_key')
    api_default_org = config.get('threatconnect', 'api_default_org')
    api_base_url = config.get('threatconnect', 'api_base_url')
except ConfigParser.NoOptionError:
    print('Could not read configuration file.')
    sys.exit(1)
```

<br/>
The configuration file should contain the following lines at a minimum:
```python
 1 [threatconnect]
 2 api_access_id = 12345678900987654321
 3 api_default_org = Acme Corp
 4 api_secret_key = aabbccddeeffgghhiijjkkllmmnnooppqqrrssttuuvvwwxxyyzz!@#$%^&*()-=
 5 api_base_url = https://api.threatconnect.com
```
Once the configuration has been set up, you should be able to run the examples in this document as long as the ThreatConnect&trade; Python SDK has been installed. See the following examples for a typical initialization of the ThreatConnect Class.

```
tc = ThreatConnect(api_access_id, api_secret_key, api_default_org, 
↪ api_base_url)
```
* * * 
<br/>
## Third-Party Dependencies

Name          | Version       | Link
------------- | ------------- | ----------------------
requests      | 2.7.0         | http://docs.python-requests.org/en/latest/
enum34        | 1.0.4         | https://pypi.python.org/pypi/enum34

## Technical Design

The ThreatConnect&trade; Python SDK was designed with a focus on abstracting the API REST calls while enabling the developer to use an enterprise level programming language. The abstraction layer attempt to provide a platform that makes combersome API request simple and provides a powerful filtering feature that will minimize the results returned from the API when possible and otherwise utilize post API filters.

## Supported Resource Types
The Python SDK support the following Resource Types.  There is also a mechanism to do manual API requests to cover any API calls that are not provided with the core functionality.

Object               | Description |
---------------------| ----------- | 
`adversaries()`      | Adversary container object. |
`bulk_indicators()`  | Bulk Indicator container object. |
`documents()`        | Document container object. |
`emails()`           | Email container object. |
`groups()`           | Group container object. |
`incidents()`        | Incident container object. |
`indicators()`       | Indicator container object. |
`owners()`           | Onwer container object. |
`signatures()`       | Signature container object. |
`threats()`          | Threat container object. |
`victims()`          | Vicitm container object. |

## First SDK Example

Now that we’ve covered setup and the Python SDK design, let’s write our first program using the Python SDK for the ThreatConnect&trade; API. We’ll create an Owners object to pull a collection of all Owners that the API credential being used have access. Once retrieved, the owners objects will be printed to the console.

```python
import ConfigParser
from threatconnect import ThreatConnect

config = ConfigParser.RawConfigParser()
config.read(config_file)

try:
    api_access_id = config.get('threatconnect', 'api_access_id')
    api_secret_key = config.get('threatconnect', 'api_secret_key')
    api_default_org = config.get('threatconnect', 'api_default_org')
    api_base_url = config.get('threatconnect', 'api_base_url')
except ConfigParser.NoOptionError:
    print('Could not read configuration file.')
    sys.exit(1)

tc = ThreatConnect(api_access_id, api_secret_key, api_default_org, api_base_url)

owners = tc.owners()

try:
    owners.retrieve()
except RunTimeErrors as e:
    print('Error: {0}'.format(e))
    sys.exit(1)

for owner in owners:
    print(owner.id)
    print(owner.name)
    print(owner.type)
```

### Code Highlights

Snippet                                   | Description                                                                       |
----------------------------------------- | --------------------------------------------------------------------------------- |
`import ConfigParser`                     | Import the ConfigParser module used to read the configuration file. |
`from threatconnect import ThreatConnect` | Import the ThreatConnect Python SDK module. |
`config = ConfigParser.RawConfigParser()` | Get an instance of ConfigParser. |
`config.read(config_file)`                | Parse the configuration file containing the API settings. |
`api_access_id = config.get('threatco...` | Get the configuration items from the config instance. |
`tc = ThreatConnect(api_access_id, ap...` | Instantiate and instance of the ThreatConnect Class. |
`owners = tc.owners()`                    | Create an Owners container object. |
`owners.retrieve()`                       | Trigger an API request to retrieve Owners. | 
`for owner in owners:`                    | Iterate through Owners generator. |
`print(owner.id)`                         | Display the 'id' property of the Owner. |

## Logging
The Python SDK allows for the setting of the log file location and debug level.  The level on the console logging can be set as well.  The default logging level for each is *critical*.

```python
...

    tc.set_tcl_file('log/tc.log', 'debug')
    tc.set_tcl_console_level('critical')
```

### Code Highlights

Snippet                                   | Description                                                                       |
----------------------------------------- | --------------------------------------------------------------------------------- |
`tc.set_tcl_file('log/tc.log', 'debug')`  | Set the destination log path and logging level. |
`tc.set_tcl_console_level('info')`        | Set the console logging level. |

## Summary 

In this section we learned:

* How to connect to the ThreatConnect&trade; API by passing reading the configuration file.
* How to get a list of Owners.
* How to iterate through a object container.
