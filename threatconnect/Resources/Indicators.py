""" standard """
import types
import urllib
import uuid

""" custom """
from threatconnect import FilterMethods
from threatconnect.Config.IndicatorType import IndicatorType
from threatconnect.Config.PropertiesAction import PropertiesAction
from threatconnect.Config.ResourceProperties import ResourceProperties
from threatconnect.Config.ResourceType import ResourceType
from threatconnect.FilterObject import FilterObject
from threatconnect.Properties.IndicatorsProperties import IndicatorsProperties
from threatconnect.RequestObject import RequestObject
from threatconnect.Resource import Resource
from threatconnect.Validate import validate_indicator, get_resource_type, get_hash_type

""" Note: PEP 8 intentionally ignored for variable/methods to match API standard. """


class Indicators(Resource):
    """ """

    def __init__(self, tc_obj):
        """ """
        super(Indicators, self).__init__(tc_obj)
        # self._object_class = IndicatorObject
        self._filter_class = IndicatorFilterObject
        self._modified_since = None

        # set properties
        properties = IndicatorsProperties(base_uri=self.base_uri)
        self._resource_type = properties.resource_type

        # create default request object for non-filtered requests
        self._request_object = RequestObject('indicators', 'default')
        self._request_object.set_http_method(properties.http_method)
        self._request_object.set_owner_allowed(properties.base_owner_allowed)
        self._request_object.set_request_uri(properties.base_path)
        self._request_object.set_resource_pagination(properties.resource_pagination)
        self._request_object.set_resource_type(properties.resource_type)
        # self._http_method = properties.http_method
        # self._owner_allowed = properties.base_owner_allowed
        # self._resource_pagination = properties.resource_pagination
        # self._request_uri = properties.base_path
        # self._resource_type = properties.resource_type

    def get_indicators(self):
        """ """
        for obj in self._objects:
            yield obj.get_indicator()

    def get_modified_since(self):
        """ """
        return self._modified_since

    def set_modified_since(self, data):
        """ """
        self._modified_since = data

    def add(self, indicator):
        """ """
        # indicator set method
        indicator_set_methods = {
            'ADDRESS': 'set_ip',
            'EMAIL_ADDRESS': 'set_address',
            'MD5': 'set_md5',
            'SHA1': 'set_sha1',
            'SHA256': 'set_sha256',
            'HOST': 'set_hostname',
            'URL': 'set_text'}

        # validate indicator
        if validate_indicator(indicator):
            # get indicator type
            resource_type = get_resource_type(indicator)

            # get properties for the object
            if resource_type.value % 10:
                resource_type = ResourceType(resource_type.value - 5)
            properties = ResourceProperties[resource_type.name].value(http_method=PropertiesAction.POST)

            # generate unique temporary id
            resource_id = uuid.uuid4().int

            # resource object
            resource_object = properties.resource_object
            # set resource id
            resource_object.set_id(resource_id)
            # set indicator
            if resource_type == ResourceType.FILE:
                set_method_name = indicator_set_methods[get_hash_type(indicator)]
            else:
                set_method_name = indicator_set_methods[resource_type.name]

            # if resource_type == ResourceType.URL:
            #     set_indicator = urllib.quote(indicator, safe='~')
            # else:
            #     set_indicator = indicator

            set_method = getattr(resource_object, set_method_name)
            set_method(indicator)
            # set resource api action
            resource_object.set_phase('add')

            # build request object
            request_object = RequestObject(self._resource_type.name, indicator)
            request_object.set_description(
                'Adding indicator ({0}).'.format(indicator))
            request_object.set_http_method(properties.http_method)
            request_object.set_request_uri(properties.post_path)
            request_object.set_owner_allowed(True)
            request_object.set_resource_pagination(False)
            request_object.set_resource_type(resource_type)

            # add to temporary object storage
            roi = self.add_master_resource_obj(resource_object, resource_id)

            res = self.get_resource_by_identity(roi)
            request_object.set_resource_object_id(id(res))
            res.set_request_object(request_object)

            # add resource object to parent object
            self.add_obj(res)

            # return object for modification
            return res
        else:
            print('({0}) is an invalid indicator.'.format(indicator))

        return None


class IndicatorFilterObject(FilterObject):
    """ """

    def __init__(self, base_uri, tcl, indicator_type_enum=None):
        """ """
        super(IndicatorFilterObject, self).__init__(base_uri, tcl)
        self._owners = []

        # pd('IndicatorFilterObject', header=True)
        # pd('indicator_type_enum', indicator_type_enum)

        # get resource type from indicator type
        if isinstance(indicator_type_enum, IndicatorType):
            # get resource type from indicator type number
            resource_type = ResourceType(indicator_type_enum.value)

            # get resource properties from resource type name
            self._properties = ResourceProperties[resource_type.name].value(base_uri=self.base_uri)
        else:
            self._properties = ResourceProperties['INDICATORS'].value(base_uri=self.base_uri)

        self._resource_type = self._properties.resource_type

        # create default request object for filtered request with only owners
        self._request_object = RequestObject('adversaries', 'default')
        self._request_object.set_http_method(self._properties.http_method)
        self._request_object.set_owner_allowed(self._properties.base_owner_allowed)
        self._request_object.set_request_uri(self._properties.base_path)
        self._request_object.set_resource_pagination(self._properties.resource_pagination)
        self._request_object.set_resource_type(self._properties.resource_type)

        # add_obj properties for filter objects with no request object
        # happens when a indicator type is specified, but no other
        # filters are provided
        # self._owner_allowed = self._properties.base_owner_allowed
        # self._request_uri = self._properties.base_path
        # self._resource_pagination = self._properties.resource_pagination
        # self._resource_type = self._properties.resource_type

        # pd('owner_allowed', self._owner_allowed)
        # pd('resource_pagination', self._resource_pagination)
        # pd('resource_type', self._resource_type)

        #
        # add_obj filter methods
        #
        for method_name in self._properties.filters:
            # pd('method_name', method_name)
            method = getattr(FilterMethods, method_name)
            setattr(self, method_name, types.MethodType(method, self))

    # special case for indicator associations
    def filter_associations(self, base_resource_type, identifier, indicator_type):
        """Get indicators associated with base resource object
        GET /v2/groups/adversaries/747266/indicators
        GET /v2/groups/adversaries/747266/indicators/addresses

        GET /v2/indicators/addresses/4.3.2.1/indicators
        GET /v2/indicators/addresses/4.3.2.1/indicators/emailAddresses

        GET /v2/victims/628/indicators
        GET /v2/victims/628/indicators/emailAddresses
        """
        base_properties = ResourceProperties[base_resource_type.name].value()

        request_uri = base_properties.base_path + '/'
        identifier = urllib.quote(identifier, safe='~')
        request_uri += str(identifier)
        if indicator_type is not None:
            indicator_properties = ResourceProperties[indicator_type.name].value()
            irt = indicator_properties.resource_type

            # update the request uri
            request_uri += '/' + indicator_properties.resource_uri_attribute
        else:
            request_uri += '/indicators'
            irt = ResourceType.INDICATORS

        description = 'Get indicator associations for {0} resource ({1}).'.format(
            base_resource_type.name.lower(), str(identifier))

        filter_type = 'indicator association'
        ro = RequestObject(
            filter_type, '{0}|{1}'.format(base_resource_type.name.lower(), identifier))
        ro.set_description(description)
        ro.set_owner_allowed(True)
        ro.set_resource_pagination(True)
        ro.set_request_uri(request_uri)
        ro.set_resource_type(irt)
        self._add_request_objects(ro)
