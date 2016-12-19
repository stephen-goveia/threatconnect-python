from collections import OrderedDict

from SharedMethods import get_hash_type, uni, urlsafe
from Config.ResourceType import ResourceType
from IndicatorObject import parse_base_indicator, IndicatorObject
from TagObject import parse_tag
from AttributeObject import parse_attribute


def parse_typed_indicator(indicator_dict, resource_obj=None, api_filter=None, request_uri=None, indicators_regex=None, tc_obj=None):
    indicator = parse_base_indicator(indicator_dict, indicators_regex=indicators_regex)

    # Get the correct type and instantiate it

    #
    # address
    #
    if 'ip' in indicator_dict:
        indicator = AddressIndicatorObject().copy_slots(indicator)
        # indicator = type('AddressIndicatorObject', (IndicatorObject, ), {'__slots__': IndicatorObject.__slots__})
        indicator.set_indicator(indicator_dict['ip'])
        if indicator.type is None:
            indicator.set_type('Address')  # set type before indicator

    #
    # email address
    #
    elif 'address' in indicator_dict:
        indicator = EmailAddressIndicatorObject().copy_slots(indicator)
        indicator.set_indicator(indicator_dict['address'])
        if indicator.type is None:
            indicator.set_type('EmailAddress')  # set type before indicator

    #
    # files
    #
    elif any(x for x in ['md5', 'sha1', 'sha256'] if x in indicator_dict):
        indicator = FileIndicatorObject().copy_slots(indicator)

        if 'md5' in indicator_dict:
            indicator.set_indicator(indicator_dict['md5'])
            if indicator.type is None:
                indicator.set_type('File')  # set type before indicator

        if 'sha1' in indicator_dict:
            indicator.set_indicator(indicator_dict['sha1'])
            if indicator.type is None:
                indicator.set_type('File')  # set type before indicator

        if 'sha256' in indicator_dict:
            indicator.set_indicator(indicator_dict['sha256'])
            if indicator.type is None:
                indicator.set_type('File')  # set type before indicator

        if 'size' in indicator_dict:
            indicator.set_size(indicator_dict['size'], update=False)

    #
    # hosts
    #
    elif any(x for x in ['hostName', 'dnsActive', 'whoisActive'] if x in indicator_dict):
        indicator = HostIndicatorObject().copy_slots(indicator)
        if 'hostName' in indicator_dict:
            indicator.set_indicator(indicator_dict['hostName'], ResourceType.HOSTS)
            if indicator.type is None:
                indicator.set_type('Host')  # set type before indicator

        if 'dnsActive' in indicator_dict:
            indicator.set_dns_active(indicator_dict['dnsActive'], update=False)

        if 'whoisActive' in indicator_dict:
            indicator.set_whois_active(indicator_dict['whoisActive'], update=False)

    #
    # urls
    #
    elif any(x for x in ['text', 'source'] if x in indicator_dict):
        indicator = UrlIndicatorObject().copy_slots(indicator)
        if 'text' in indicator_dict:
            indicator.set_indicator(indicator_dict['text'], ResourceType.URLS)

        if 'source' in indicator_dict:
            indicator.set_source(indicator_dict['source'], update=False)

    #
    # custom
    #
    else:
        indicator = CustomIndicatorObject().copy_slots(indicator)
        # type MUST exist as well as tc_obj for us to continue
        _type = indicator_dict.get('type', None)
        if _type is None or tc_obj is None:
            raise AttributeError()

        if _type not in tc_obj.custom_indicator_types:
            raise AttributeError()

        # get the type and field names, then check the dict for those names
        field_names = tc_obj.get_fields_for_custom_type(_type)
        for field_name in field_names:
            field_val = "{0!s}".format(indicator_dict.get(field_name)).strip()
            custom_field = CustomIndicatorField(field_name, value=field_val)
            indicator.add_custom_field(custom_field)

        # field_labels = tc_obj.custom_indicator_types.get(_type)
        # for i in range(1, 4):
        #     field_name = field_labels.get('value{0!s}Label'.format(i), None)
        #     if field_name is not None:
        #         # the field name must exist in indicator_dict if it exists in custom_indicator_types's dict
        #         field_val = "{0!s}".format(indicator_dict.get(field_name)).strip()
        #         fields[field_name] = field_val

    if 'summary' in indicator_dict:
        indicator_val = indicator_dict.get('summary')
        if indicator.resource_type == ResourceType.CUSTOM_INDICATORS:
            # summary comes in as a colon delimited string; we don't want that
            _type = indicator_dict.get('_type', None)
            if _type is None or tc_obj is None:
                raise AttributeError()

            field_names = tc_obj.get_fields_for_custom_type(_type)
            field_values = indicator_val.split(" : ")
            for i in range(0, 3):
                custom_field = CustomIndicatorField(field_names[i], value=field_values[i])
                indicator.add_custom_field(custom_field)
        else:
            resource_type = indicator.resource_type
            indicator.set_indicator(indicator_dict['summary'], resource_type)

    #
    # attributes
    #
    if 'attribute' in indicator_dict:
        for attribute_dict in indicator_dict['attribute']:
            attribute = parse_attribute(attribute_dict, indicator)
            indicator.add_attribute(attribute)

    #
    # tag
    #
    if 'tag' in indicator_dict:
        for tag_dict in indicator_dict['tag']:
            tag = parse_tag(tag_dict)
            indicator.add_tag(tag)

    #
    # observations
    #
    if 'observationCount' in indicator_dict:
        indicator.set_observation_count(indicator_dict['observationCount'])

    if 'lastObserved' in indicator_dict:
        indicator.set_last_observed(indicator_dict['last_observed'])


    #
    # handle both resource containers and individual objects
    #
    if resource_obj is not None:
        # store the resource object in the master resource object list
        # must be submitted after parameters are set for indexing to work
        roi = resource_obj.add_master_resource_obj(indicator, indicator_dict['id'])

        # BCS - This causes a bug on searching for a single indicator over multiple
        #       owners, only 1 indicator is returned.
        # roi = resource_obj.add_master_resource_obj(indicator, indicator.indicator)

        # retrieve the resource object and update data
        return resource_obj.get_resource_by_identity(roi)

    #
    # filter (set after retrieving stored object)
    #
    if api_filter is not None:
        indicator.add_matched_filter(api_filter)

    #
    # request_uri (set after retrieving stored object)
    #
    if request_uri is not None:
        indicator.add_request_uri(request_uri)

    return indicator


class AddressIndicatorObject(IndicatorObject):
    __slots__ = ()

    def __init__(self):
        super(AddressIndicatorObject, self).__init__(resource_type_enum=ResourceType.ADDRESSES)

    def set_indicator(self, data, resource_type=None, update=True):
        self._ip = uni(data)
        self._reference_indicator = urlsafe(self._ip)

        # additional resource type specific attributes
        self._properties['_ip'] = {
            'api_field': 'ip',
            'method': 'set_indicator',
            'required': True,
        }

    #
    #   Read-Only
    #
    @property
    def indicator(self):
        return self._ip


class EmailAddressIndicatorObject(IndicatorObject):
    # __slots__ = (
    #     '_address',
    # )
    __slots__ = ()

    def __init__(self):
        super(EmailAddressIndicatorObject, self).__init__(resource_type_enum=ResourceType.EMAIL_ADDRESSES)

    def set_indicator(self, data, resource_type=None, update=True):
        self._address = uni(data)
        self._reference_indicator = urlsafe(self._address)

        # additional resource type specific attributes
        self._properties['_address'] = {
            'api_field': 'address',
            'method': 'set_indicator',
            'required': True,
        }

    #
    #   Read-Only
    #
    @property
    def indicator(self):
        return self._address

    # @property
    # def address(self):
    #     return self._address


class FileIndicatorObject(IndicatorObject):
    # __slots__ = (
    #     '_file_occurrences'
    #     '_md5',
    #     '_sha1',
    #     '_sha256',
    #     '_size'
    # )
    __slots__ = ()

    def __init__(self):
        super(FileIndicatorObject, self).__init__(resource_type_enum=ResourceType.FILES)

    def set_indicator(self, data, resource_type=None, update=True):
        # handle different hash type
        hash_type = get_hash_type(data)
        if hash_type == 'MD5':
            self._md5 = data
            if self._reference_indicator is None:  # reference indicator for attr, tag, etc adds
                self._reference_indicator = urlsafe(self._md5)
        elif hash_type == 'SHA1':
            self._sha1 = data
            if self._reference_indicator is None:  # reference indicator for attr, tag, etc adds
                self._reference_indicator = urlsafe(self._sha1)
        elif hash_type == 'SHA256':
            self._sha256 = data
            if self._reference_indicator is None:  # reference indicator for attr, tag, etc adds
                self._reference_indicator = urlsafe(self._sha256)

        self._properties['_md5'] = {
            'api_field': 'md5',
            'method': 'set_indicator',
            'required': True,
        }
        self._properties['_sha1'] = {
            'api_field': 'sha1',
            'method': 'set_indicator',
            'required': True,
        }
        self._properties['_sha256'] = {
            'api_field': 'sha256',
            'method': 'set_indicator',
            'required': True,
        }
        self._properties['_size'] = {
            'api_field': 'size',
            'method': 'set_size',
            'required': False,
        }

        if update and self._phase == 0:
            self._phase = 2

    # @property
    # def file_occurrences(self):
    #     """ """
    #     return self._file_occurrences
    #
    # def add_file_occurrence(self, data_obj):
    #     """Read-Only indicator metadata"""
    #     self._file_occurrences.append(data_obj)
    #
    # @property
    # def size(self):
    #     """ """
    #     return self._size
    #
    # def set_size(self, data, update=True):
    #     """ """
    #     self._size = uni(str(data))
    #
    #     if update and self._phase == 0:
    #         self._phase = 2

    #
    #   Read-Only
    #
    @property
    def indicator(self):
        return {
            'md5': self._md5,
            'sha1': self._sha1,
            'sha256': self._sha256
        }

    # @property
    # def md5(self):
    #     """ """
    #     return self._md5
    #
    # @property
    # def sha1(self):
    #     """ """
    #     return self._sha1
    #
    # @property
    # def sha256(self):
    #     """ """
    #     return self._sha256


class HostIndicatorObject(IndicatorObject):
    # __slots__ = (
    #     '_dns_active',
    #     '_dns_resolutions'
    #     '_hostname',
    #     '_whois_active',
    #     )
    __slots__ = ()

    def __init__(self):
        super(HostIndicatorObject, self).__init__(resource_type_enum=ResourceType.HOSTS)

    def set_indicator(self, data, resource_type=None, update=True):
        self._hostname = uni(data)
        self._reference_indicator = urlsafe(self._hostname)

        # additional resource type specific attributes
        self._properties['_hostname'] = {
            'api_field': 'hostName',
            'method': 'set_indicator',
            'required': True,
        }
        self._properties['_dns_active'] = {
            'api_field': 'dnsActive',
            'method': 'set_dns_active',
            'required': False,
        }
        self._properties['_whois_active'] = {
            'api_field': 'whoisActive',
            'method': 'set_whois_active',
            'required': False,
        }

    @property
    def dns_active(self):
        """ """
        return self._dns_active

    def set_dns_active(self, data, update=True):
        """ """
        self._dns_active = uni(data)

        if update and self._phase == 0:
            self._phase = 2

    @property
    def dns_resolutions(self):
        """ """
        return self._dns_resolutions

    def add_dns_resolution(self, data_obj):
        """Read-Only indicator metadata"""
        if isinstance(data_obj, list):
            self._dns_resolutions.extend(data_obj)
        else:
            self._dns_resolutions.append(data_obj)

    @property
    def whois_active(self):
        """ """
        return self._whois_active

    def set_whois_active(self, data, update=True):
        """ """
        self._whois_active = uni(data)

        if update and self._phase == 0:
            self._phase = 2

    #
    #   Read-Only
    #
    @property
    def indicator(self):
        return self._hostname

    @property
    def hostname(self):
        return self._hostname


class UrlIndicatorObject(IndicatorObject):
    __slots__ = ()

    def __init__(self):
        super(UrlIndicatorObject, self).__init__(resource_type_enum=ResourceType.URLS)

    def set_indicator(self, data, resource_type=None, update=True):
        self._text = uni(data)
        self._reference_indicator = urlsafe(self._text)

        # additional resource type specific attributes
        self._properties['_text'] = {
            'api_field': 'text',
            'method': 'set_indicator',
            'required': True,
        }

    @property
    def source(self):
        """ """
        return self._source

    def set_source(self, data, update=True):
        """ """
        self._source = uni(data)

        if update and self._phase == 0:
            self._phase = 2

    #
    #   Read-Only
    #
    @property
    def indicator(self):
        return self._text

    @property
    def text(self):
        return self._text


class CustomIndicatorField(object):
    __slots__ = (
        '_label',
        '_value',
        '_type'
    )

    def __init__(self, label, value=None, type=None):
        self._label = label
        self._value = value
        self._type = type

    @property
    def label(self):
        return self._label

    @property
    def value(self):
        return self._value

    @property
    def type(self):
        return self._type


class CustomIndicatorObject(IndicatorObject):
    __slots__ = ()

    def __init__(self):
        super(CustomIndicatorObject, self).__init__(resource_type_enum=ResourceType.CUSTOM_INDICATORS)

    def set_indicator(self, data, resource_type=None, update=True):
        self._reference_indicator = urlsafe(data)
        if resource_type == ResourceType.CUSTOM_INDICATORS:
            data = data if isinstance(data, list) else [data]
            self._custom_fields = uni(data)

    @property
    def indicator(self):
        """
        returns custom indicator as a map of 1-3 fields
        which when delimited represent the indicator
        """
        # get first value (required) and check if there are others
        # TODO: Do we not want the fields' names? This only gets the fields' values

        # indicator = ':'.join(self._custom_fields.items().values())
        # return self._custom_fields.values()
        return ' : '.join(self._custom_fields.values())



    # def set_api_uri(self, api_uri):
    #     self._api_uri = api_uri
    #
    # @property
    # def api_uri(self):
    #     return self._api_uri


    # @property
    # def name(self):
    #     return self._name
    #
    # def set_name(self, name):
    #     self._name = uni(name)

    # @property
    # def custom_fields(self):
    #     return self._custom_fields
    #
    # def set_custom_fields(self, fields):
    #     if isinstance(fields, OrderedDict):
    #         self._custom_fields = fields
    #
    # def add_custom_field(self, field):
    #     if isinstance(field, CustomIndicatorField):
    #         self._custom_fields.append(field)

    # @property
    # def values(self):
    #     return self._values
    #
    # def set_values(self, values):
    #     if isinstance(values, list):
    #         self._values = values
    #
    # def add_value(self, value):
    #     if not len(self.values) >= 3:
    #         self._values.append(value)

    # def set_custom_fields(self, data, update=True):
    #     self._custom_fields = uni(data)
    #
    # @property
    # def custom_fields(self):
    #     return self._custom_fields
    #
    # def set_custom_field_types(self, custom_field_types):
    #     self._custom_field_types = uni(custom_field_types)
    #
    # @property
    # def custom_field_types(self):
    #     return self._custom_field_types

