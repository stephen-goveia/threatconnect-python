""" standard """
import types

""" custom """
from threatconnect import FilterMethods
from threatconnect.Properties.OwnersProperties import OwnersProperties
from threatconnect.FilterObject import FilterObject
from threatconnect.RequestObject import RequestObject
from threatconnect.Resource import Resource

""" Note: PEP 8 intentionally ignored for variable/methods to match API standard. """


class Owners(Resource):
    """ """
    def __init__(self, tc_obj):
        """ """
        super(Owners, self).__init__(tc_obj)
        self._filter_class = OwnerFilterObject

        # set properties
        properties = OwnersProperties(base_uri=self.base_uri)
        self._resource_type = properties.resource_type

        # create default request object for non-filtered requests
        self._request_object = RequestObject('owners', 'default')
        self._request_object.set_http_method(properties.http_method)
        self._request_object.set_owner_allowed(properties.base_owner_allowed)
        self._request_object.set_request_uri(properties.base_path)
        self._request_object.set_resource_pagination(properties.resource_pagination)
        self._request_object.set_resource_type(properties.resource_type)

    def get_owner_by_id(self, data):
        for obj in self._objects:
            if obj.get_id() == data:
                return obj
        return None

    def get_owner_by_name(self, data):
        for obj in self._objects:
            if obj.get_name() == data:
                return obj
        return None

    def get_owner_names(self):
        owner_names = []
        for obj in self._objects:
            owner_names.append(obj.get_name())
        return owner_names


class OwnerFilterObject(FilterObject):
    """ """

    def __init__(self, base_uri, tcl):
        """ """
        super(OwnerFilterObject, self).__init__(base_uri, tcl)
        # TODO: this is a quick hack and needs to be fixed
        self._owners = []
        self._property_class = OwnersProperties
        self._properties_class = OwnersProperties

        # define properties for resource type
        self._properties = self._properties_class(base_uri=self.base_uri)
        self._resource_type = self._properties.resource_type

        # create default request object for filtered request with only owners
        self._request_object = RequestObject('owners', 'default')
        self._request_object.set_http_method(self._properties.http_method)
        self._request_object.set_owner_allowed(self._properties.base_owner_allowed)
        self._request_object.set_request_uri(self._properties.base_path)
        self._request_object.set_resource_pagination(self._properties.resource_pagination)
        self._request_object.set_resource_type(self._properties.resource_type)

        #
        # add_obj filter methods
        #
        for method_name in self._properties.filters:
            method = getattr(FilterMethods, method_name)
            setattr(self, method_name, types.MethodType(method, self))
