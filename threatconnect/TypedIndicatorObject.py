from collections import OrderedDict
from SharedMethods import get_hash_type, uni, urlsafe



class AddressIndicatorObject(object):

    def set_indicator(self, data, update=True):
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

    @property
    def ip(self):
        return self._ip


class EmailAddressIndicatorObject(object):

    def set_indicator(self, data, update=True):
        self._address = uni(data)
        self._reference_indicator = urlsafe(self._address)

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
        return self._address

    @property
    def address(self):
        return self._address


class FileIndicatorObject(object):

    def set_indicator(self, data, update=True):
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

    @property
    def file_occurrences(self):
        """ """
        return self._file_occurrences

    def add_file_occurrence(self, data_obj):
        """Read-Only indicator metadata"""
        self._file_occurrences.append(data_obj)

    @property
    def size(self):
        """ """
        return self._size

    def set_size(self, data, update=True):
        """ """
        self._size = uni(str(data))

        if update and self._phase == 0:
            self._phase = 2

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

    @property
    def md5(self):
        """ """
        return self._md5

    @property
    def sha1(self):
        """ """
        return self._sha1

    @property
    def sha256(self):
        """ """
        return self._sha256


class HostIndicatorObject(object):

    def set_indicator(self, data, update=True):
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


class UrlIndicatorObject(object):

    def set_indicator(self, data, update=True):
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


class CustomIndicatorObject(object):

    def set_indicator(self, data, update=True):
        if isinstance(data, OrderedDict):
            self._custom_fields = uni(data)

    @property
    def indicator(self):
        """
        returns custom indicator as a map of 1-3 fields
        which when delimited represent the indicator
        """
        # get first value (required) and check if there are others
        # TODO: Do we not want the fields' names? This only gets the fields' values

        key_val = self._custom_fields.items()
        indicator = None

        for i in range(0, len(key_val)):
            if i is 0:
                indicator = '{}'.format(key_val[i][1])
            else:
                indicator = '{}:{}'.format(indicator, key_val[i][1])

        return indicator

    @property
    def custom_fields(self):
        return self._custom_fields
