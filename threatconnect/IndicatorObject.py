""" standard """
try:
    from StringIO import StringIO
except ImportError:
    from io import StringIO

""" custom """
from collections import OrderedDict

from AttributeObject import parse_attribute
from Config.ResourceType import ResourceType
from ErrorCodes import ErrorCodes
from SharedMethods import get_resource_type, get_hash_type, get_resource_indicator_type
from SharedMethods import uni, urlsafe
from TagObject import parse_tag


def parse_indicator(indicator_dict, resource_obj=None, api_filter=None, request_uri=None, indicators_regex=None):
    """ """
    # indicator object
    indicator = IndicatorObject()

    #
    # standard values
    #
    indicator.set_date_added(indicator_dict['dateAdded'])
    indicator.set_id(indicator_dict['id'])
    indicator.set_last_modified(indicator_dict['lastModified'])
    indicator.set_weblink(indicator_dict['webLink'])

    #
    # optional values
    #
    if 'type' in indicator_dict:
        indicator.set_type(indicator_dict['type'])  # set type before indicator

    if 'confidence' in indicator_dict:
        indicator.set_confidence(indicator_dict['confidence'], update=False)
    if 'description' in indicator_dict:
        indicator.set_description(indicator_dict['description'], update=False)
    if 'owner' in indicator_dict:  # nested owner for single indicator result
        indicator.set_owner_name(indicator_dict['owner']['name'])
    if 'ownerName' in indicator_dict:
        indicator.set_owner_name(indicator_dict['ownerName'])
    if 'rating' in indicator_dict:
        indicator.set_rating(indicator_dict['rating'], update=False)
    if 'summary' in indicator_dict:
        resource_type = get_resource_type(indicators_regex, indicator_dict['summary'])
        indicator.set_indicator(indicator_dict['summary'], resource_type)
    if 'threatAssessConfidence' in indicator_dict:
        indicator.set_threat_assess_confidence(indicator_dict['threatAssessConfidence'])
    if 'threatAssessRating' in indicator_dict:
        indicator.set_threat_assess_rating(indicator_dict['threatAssessRating'])

    #
    # address
    #
    if 'ip' in indicator_dict:
        indicator.set_indicator(indicator_dict['ip'], ResourceType.ADDRESSES)
        if indicator.type is None:
            indicator.set_type('Address')  # set type before indicator

    #
    # email address
    #
    if 'address' in indicator_dict:
        indicator.set_indicator(indicator_dict['address'], ResourceType.EMAIL_ADDRESSES)
        if indicator.type is None:
            indicator.set_type('EmailAddress')  # set type before indicator

    #
    # files
    #
    if 'md5' in indicator_dict:
        indicator.set_indicator(indicator_dict['md5'], ResourceType.FILES)
        if indicator.type is None:
            indicator.set_type('File')  # set type before indicator

    if 'sha1' in indicator_dict:
        indicator.set_indicator(indicator_dict['sha1'], ResourceType.FILES)
        if indicator.type is None:
            indicator.set_type('File')  # set type before indicator

    if 'sha256' in indicator_dict:
        indicator.set_indicator(indicator_dict['sha256'], ResourceType.FILES)
        if indicator.type is None:
            indicator.set_type('File')  # set type before indicator

    if 'size' in indicator_dict:
        indicator.set_size(indicator_dict['size'], update=False)

    #
    # hosts
    #
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
    if 'text' in indicator_dict:
        indicator.set_indicator(indicator_dict['text'], ResourceType.URLS)
        if indicator.type is None:
            indicator.set_type('URL')  # set type before indicator

    if 'source' in indicator_dict:
        indicator.set_source(indicator_dict['source'], update=False)

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
    # custom fields (anything not in __slots__)
    #
    custom_keys = [key for key in indicator_dict if key not in [slot.replace('_', '') for slot in IndicatorObject.__slots__]]
    if len(custom_keys) > 0:
        custom_dict = OrderedDict()
        for key in custom_keys:
            custom_dict[key] = indicator_dict[key]
        indicator.set_custom_fields(custom_dict)


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


class IndicatorObject(object):
    __slots__ = (
        '_address',  # email address specific indicator
        '_attributes',
        '_confidence',
        '_custom_fields',   # custom indicator type specific
        '_date_added',
        '_description',
        '_dns_active',  # host indicator type specific
        '_dns_resolutions',  # host indicator type specific
        '_file_occurrences',  # file indicator type specific
        '_hostname',  # host specific indicator
        '_id',
        '_ip',  # address specific indicator
        '_size',  # file indicator type specific
        '_last_modified',
        '_last_observed',   # most recent observation date
        '_matched_filters',
        '_md5',  # file specific indicator
        '_observation_count',   # most recent observation count
        '_owner_name',
        '_phase',  # 0 - new; 1 - add; 2 - update
        '_properties',
        '_rating',
        '_reference_indicator',
        '_request_uris',
        '_resource_type',
        '_security_label',
        '_sha1',  # file specific indicator
        '_sha256',  # file specific indicator
        '_source',  # url indicator type specific
        '_tags',
        '_text',  # url specific indicator
        '_threat_assess_confidence',
        '_threat_assess_rating',
        '_type',
        '_weblink',
        '_whois_active',  # host indicator type specific
        '_reload_attributes',
    )

    def __init__(self, resource_type_enum=None):
        self._attributes = []
        self._address = None  # email indicator type specific
        self._confidence = None
        self._custom_fields = None  # custom indicator type specific
        self._date_added = None
        self._description = None
        self._dns_active = None  # host indicator type specific
        self._dns_resolutions = []  # host indicator type specific
        self._file_occurrences = []  # file indicator type specific
        self._size = None  # file indicator type specific
        # self._groups = []
        self._id = None
        self._hostname = None  # host indicator type specific
        self._ip = None  # address indicator type specific
        self._last_modified = None
        self._last_observed = None
        self._matched_filters = []
        self._md5 = None  # file indicator type specific
        self._observation_count = None
        self._owner_name = None
        self._phase = 0
        self._reload_attributes = False
        self._properties = {
            '_confidence': {
                'api_field': 'confidence',
                'method': 'set_confidence',
                'required': False,
            },
            '_rating': {
                'api_field': 'rating',
                'method': 'set_rating',
                'required': False,
            }
        }
        self._rating = None
        self._reference_indicator = None
        self._request_uris = []
        self._resource_type = resource_type_enum
        self._security_label = None
        self._sha1 = None  # file indicator type specific
        self._sha256 = None  # file indicator type specific
        self._source = None  # url indicator type specific
        self._tags = []
        self._text = None  # url indicator type specific
        self._threat_assess_confidence = None
        self._threat_assess_rating = None
        self._type = None
        self._weblink = None
        self._whois_active = None  # host indicator type specific

    """ shared indicator methods """

    #
    # confidence
    #
    @property
    def confidence(self):
        """ """
        return self._confidence

    def set_confidence(self, data, update=True):
        """Read-Write indicator metadata"""
        if isinstance(data, int):
            if 0 <= data <= 100:
                self._confidence = data
            else:
                raise AttributeError(ErrorCodes.e10010.value.format(data))
        else:
            raise AttributeError(ErrorCodes.e10011.value.format(data))

        if update and self._phase == 0:
            self._phase = 2

    #
    # custom_fields
    #
    @property
    def custom_fields(self):
        return self._custom_fields

    def set_custom_fields(self, data, update=True):
        if self.resource_type == ResourceType.CUSTOM_INDICATORS:
            self._custom_fields = data
        else:
            raise AttributeError(ErrorCodes.e10100.value)

    #
    # date_added
    #
    @property
    def date_added(self):
        """ """
        return self._date_added

    def set_date_added(self, data):
        """Read-Only indicator metadata"""
        self._date_added = data

    #
    # description
    #
    @property
    def description(self):
        """ """
        return self._description

    def set_description(self, data, update=True):
        """Read-Write indicator metadata"""
        self._description = uni(data)

        if update and self._phase == 0:
            self._phase = 2

    #
    # dns_active (host indicator type specific)
    #
    @property
    def dns_active(self):
        """ """
        if self._resource_type == ResourceType.HOSTS:
            return self._dns_active
        else:
            raise AttributeError(ErrorCodes.e10100.value)

    def set_dns_active(self, data, update=True):
        """ """
        if self._resource_type == ResourceType.HOSTS:
            self._dns_active = uni(data)
        else:
            raise AttributeError(ErrorCodes.e10100.value)

        if update and self._phase == 0:
            self._phase = 2

    #
    # dns resolutions (host indicator type specific)
    #
    @property
    def dns_resolutions(self):
        """ """
        if self._resource_type == ResourceType.HOSTS:
            return self._dns_resolutions
        else:
            raise AttributeError(ErrorCodes.e10110.value)

    def add_dns_resolution(self, data_obj):
        """Read-Only indicator metadata"""
        if self._resource_type == ResourceType.HOSTS:
            if isinstance(data_obj, list):
                self._dns_resolutions.extend(data_obj)
            else:
                self._dns_resolutions.append(data_obj)

        else:
            raise AttributeError(ErrorCodes.e10110.value)

    #
    # file_occurrences (file indicator type specific)
    #
    @property
    def file_occurrences(self):
        """ """
        if self._resource_type == ResourceType.FILES:
            return self._file_occurrences
        else:
            raise AttributeError(ErrorCodes.e10120.value)

    def add_file_occurrence(self, data_obj):
        """Read-Only indicator metadata"""
        if self._resource_type == ResourceType.FILES:
            self._file_occurrences.append(data_obj)
        else:
            raise AttributeError(ErrorCodes.e10120.value)

    #
    # id
    #
    @property
    def id(self):
        """ """
        return self._id

    def set_id(self, data):
        """Read-Only indicator metadata"""
        if isinstance(data, (int, long)):
            self._id = data
        else:
            raise AttributeError(ErrorCodes.e10020.value.format(data))

    #
    # indicator
    #
    @property
    def indicator(self):
        """ """
        if self._resource_type == ResourceType.ADDRESSES:
            return self._ip
        elif self._resource_type == ResourceType.EMAIL_ADDRESSES:
            return self._address
        elif self._resource_type == ResourceType.FILES:
            return {
                'md5': self._md5,
                'sha1': self._sha1,
                'sha256': self._sha256,
            }
        elif self._resource_type == ResourceType.HOSTS:
            return self._hostname
        elif self._resource_type == ResourceType.URLS:
            return self._text
        else:
            raise AttributeError(ErrorCodes.e10030.value)

    def set_indicator(self, data, resource_type, update=True):
        """Read-Write indicator metadata"""
        if self._resource_type is None:
            self._resource_type = resource_type

        # if get_resource_type return None error.
        if not isinstance(self._resource_type, ResourceType):
            raise AttributeError(ErrorCodes.e10030.value)

        #
        # address
        #
        if self._resource_type == ResourceType.ADDRESSES:
            self._ip = uni(data)
            self._reference_indicator = urlsafe(self._ip)

            # additional resource type specific attributes
            self._properties['_ip'] = {
                'api_field': 'ip',
                'method': 'set_indicator',
                'required': True,
            }

        #
        # email_address
        #
        if self._resource_type == ResourceType.EMAIL_ADDRESSES:
            self._address = uni(data)
            self._reference_indicator = urlsafe(self._address)

            # additional resource type specific attributes
            self._properties['_address'] = {
                'api_field': 'address',
                'method': 'set_indicator',
                'required': True,
            }

        #
        # files
        #
        if self._resource_type == ResourceType.FILES:
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

        #
        # hosts
        #
        if self._resource_type == ResourceType.HOSTS:
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

        #
        # urls
        #
        if self._resource_type == ResourceType.URLS:
            self._text = uni(data)
            self._reference_indicator = urlsafe(self._text)

            # additional resource type specific attributes
            self._properties['_text'] = {
                'api_field': 'text',
                'method': 'set_indicator',
                'required': True,
            }

    #
    # last_modified
    #
    @property
    def last_modified(self):
        """ """
        return self._last_modified

    def set_last_modified(self, data):
        """Read-Only indicator metadata"""
        self._last_modified = data

    #
    # last_observed
    #
    @property
    def last_observed(self):
        """ """
        return self._last_observed

    def set_last_observed(self, data):
        """ Read-Only observation data """
        self._last_observed = data


    #
    # observation_count
    #

    @property
    def observation_count(self):
        """ """
        return self._observation_count

    def set_observation_count(self, data):
        """ Read-Only observation data """
        self._observation_count = data

    #
    # owner_name
    #
    @property
    def owner_name(self):
        """ """
        return self._owner_name

    def set_owner_name(self, data):
        """Read-Only indicator metadata"""
        self._owner_name = uni(data)

    #
    # matched filters
    #
    @property
    def matched_filters(self):
        """ """
        return self._matched_filters

    def add_matched_filter(self, data):
        """ """
        if data not in self._matched_filters and data is not None:
            self._matched_filters.append(data)

    #
    # rating
    #
    @property
    def rating(self):
        """ """
        return self._rating

    def set_rating(self, data, update=True):
        """Read-Write indicator metadata"""
        self._rating = data

        # determine if POST or PUT
        if update and self._phase == 0:
            self._phase = 2

    #
    # size (file indicator type specific)
    #
    @property
    def size(self):
        """ """
        if self._resource_type == ResourceType.FILES:
            return self._size
        else:
            raise AttributeError(ErrorCodes.e10130.value)

    def set_size(self, data, update=True):
        """ """
        if self._resource_type == ResourceType.FILES:
            self._size = uni(str(data))
        else:
            raise AttributeError(ErrorCodes.e10130.value)

        if update and self._phase == 0:
            self._phase = 2

    #
    # source (url indicator type specific)
    #
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
    # threat assesses confidence
    #
    @property
    def threat_assess_confidence(self):
        """ """
        return self._threat_assess_confidence

    def set_threat_assess_confidence(self, data):
        """Read-Only indicator metadata"""
        self._threat_assess_confidence = data

    #
    # threat assesses rating
    #
    @property
    def threat_assess_rating(self):
        """ """
        return self._threat_assess_rating

    def set_threat_assess_rating(self, data):
        """Read-Only indicator metadata"""
        self._threat_assess_rating = data

    #
    # type
    #
    @property
    def type(self):
        """ """
        return self._type

    def set_type(self, data):
        """ """
        self._type = uni(data)
        self._resource_type = get_resource_indicator_type(self._type)

    #
    # weblink
    #
    @property
    def weblink(self):
        """ """
        return self._weblink

    def set_weblink(self, data):
        """ """
        self._weblink = uni(data)

    #
    # whois_active (host indicator type specific)
    #
    @property
    def whois_active(self):
        """ """
        if self._resource_type == ResourceType.HOSTS:
            return self._whois_active
        else:
            raise AttributeError(ErrorCodes.e10140.value)

    def set_whois_active(self, data, update=True):
        """ """
        if self._resource_type == ResourceType.HOSTS:
            self._whois_active = uni(data)
        else:
            raise AttributeError(ErrorCodes.e10140.value)

        if update and self._phase == 0:
            self._phase = 2

    #
    # methods
    #
    @property
    def request_uris(self):
        return self._request_uris

    def add_request_uri(self, data):
        """ """
        if data not in self._request_uris:
            self._request_uris.append(data)

    #
    # attributes
    #
    @property
    def attributes(self):
        """ """
        return self._attributes

    def add_attribute(self, data_obj):
        """collection of attributes objects"""
        self._attributes.append(data_obj)

    # #
    # # group object (adversaries, emails, incidents, documents, victims)
    # #
    # @property
    # def groups(self):
    #     """ """
    #     return self._groups
    #
    # def add_group(self, data_obj):
    #     """collection of associated group objects"""
    #     self._groups.append(data_obj)

    #
    # security label
    #
    @property
    def security_label(self):
        """ """
        return self._security_label

    def set_security_label(self, data_obj):
        self.add_security_label(data_obj)

    def add_security_label(self, data_obj):
        """security label"""
        self._security_label.append(data_obj)

    #
    # tags
    #
    @property
    def tags(self):
        """ """
        return self._tags

    def add_tag(self, data_obj):
        """collection of tag objects"""
        self._tags.append(data_obj)

    #
    # phase
    #
    @property
    def phase(self):
        """ """
        return self._phase

    def set_phase(self, data):
        """ """
        self._phase = data

    #
    # resource_type
    #
    @property
    def resource_type(self):
        """ """
        return self._resource_type

    # def set_resource_type(self, data):
    #     """ """
    #     self._resource_type = data

    #
    # validate
    #
    @property
    def validate(self):
        """ validate all required fields """
        for prop, values in self._properties.items():
            # special check for file hash
            if prop in ['_md5', '_sha1', '_sha256']:
                # if any hash is not None then proceed
                if self._md5 or self._sha1 or self._sha256:
                    continue

            if values['required']:
                # fail validation if any required field is None
                if getattr(self, prop) is None:
                    return False

        # validated
        return True

    #
    # add print method
    #
    def __str__(self):
        """allow object to be displayed with print"""

        printable_string = '\n{0!s:_^80}\n'.format('Resource Object Properties')

        #
        # retrievable methods
        #
        printable_string += '{0!s:40}\n'.format('Retrievable Methods')
        printable_string += ('  {0!s:<28}: {1!s:<50}\n'.format('id', self.id))
        if isinstance(self.indicator, dict):
            printable_string += ('  {0!s:<28} {1!s:<50}\n'.format('indicator', ''))
            printable_string += ('   {0!s:<10}: {1!s:<70}\n'.format('md5', self.indicator['md5']))
            printable_string += ('   {0!s:<10}: {1!s:<70}\n'.format('sha1', self.indicator['sha1']))
            printable_string += ('   {0!s:<10}: {1!s:<70}\n'.format('sha256', self.indicator['sha256']))
        else:
            printable_string += ('  {0!s:<28}: {1!s:<50}\n'.format('indicator', self.indicator))
        printable_string += ('  {0!s:<28}: {1!s:<50}\n'.format('resource_type', self.resource_type))
        printable_string += ('  {0!s:<28}: {1!s:<50}\n'.format('owner_name', self.owner_name))
        printable_string += ('  {0!s:<28}: {1!s:<50}\n'.format('date_added', self.date_added))
        printable_string += ('  {0!s:<28}: {1!s:<50}\n'.format('last_modified', self.last_modified))
        printable_string += ('  {0!s:<28}: {1!s:<50}\n'.format('description', self.description))
        printable_string += ('  {0!s:<28}: {1!s:<50}\n'.format('confidence', self.confidence))
        printable_string += ('  {0!s:<28}: {1!s:<50}\n'.format('rating', self.rating))
        printable_string += ('  {0!s:<28}: {1!s:<50}\n'.format('threat_assess_confidence',
                                                               self.threat_assess_confidence))
        printable_string += ('  {0!s:<28}: {1!s:<50}\n'.format('threat_assess_rating', self.threat_assess_rating))
        printable_string += ('  {0!s:<28}: {1!s:<50}\n'.format('security_label', self.security_label))
        # printable_string += ('  {0!s:<28}: {1!s:<50}\n'.format('type', self.type))
        printable_string += ('  {0!s:<28}: {1!s:<50}\n'.format('weblink', self.weblink))

        #
        # writable methods
        #
        printable_string += '\n{0!s:40}\n'.format('Writable Properties')
        for prop, values in sorted(self._properties.items()):
            printable_string += ('  {0!s:<28}: {1:<50}\n'.format(
                values['api_field'], '{0!s} (Required: {1!s})'.format(values['method'], str(values['required']))))

        #
        # object information
        #
        printable_string += '\n{0!s:40}\n'.format('Object Information')
        printable_string += ('  {0!s:<28}: {1!s:<50}\n'.format('phase', self.phase))

        #
        # matched filter
        #
        if len(self.matched_filters) > 0:
            printable_string += '\n{0!s:40}\n'.format('Matched Filters')
            for item in sorted(self.matched_filters):
                printable_string += ('  {0!s:<28}: {1!s:<50}\n'.format('matched filter', item))

        #
        # request uri's
        #
        if len(self.request_uris) > 0:
            printable_string += '\n{0!s:40}\n'.format('Request URI\'s')
            for item in sorted(self.request_uris):
                printable_string += ('  {0!s:<28}: {1!s:<50}\n'.format('', item))

        return printable_string