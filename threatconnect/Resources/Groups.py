""" std modules """
import types

""" custom modules """
from threatconnect import FilterMethods
from threatconnect.Config.ResourceProperties import ResourceProperties
from threatconnect.Config.ResourceType import ResourceType
from threatconnect.FilterObject import FilterObject
from threatconnect.Properties.GroupsProperties import GroupsProperties
from threatconnect.RequestObject import RequestObject
from threatconnect.Resource import Resource

""" Note: PEP 8 intentionally ignored for variable/methods to match API standard. """


class Groups(Resource):
    """ """

    def __init__(self, tc_obj):
        """ """
        super(Groups, self).__init__(tc_obj)
        self._filter_class = GroupFilterObject

        # set properties
        properties = GroupsProperties(base_uri=self.base_uri)
        self._resource_type = properties.resource_type

        # create default request object for non-filtered requests
        self._request_object = RequestObject('groups', 'default')
        self._request_object.set_http_method(properties.http_method)
        self._request_object.set_owner_allowed(properties.base_owner_allowed)
        self._request_object.set_request_uri(properties.base_path)
        self._request_object.set_resource_pagination(properties.resource_pagination)
        self._request_object.set_resource_type(properties.resource_type)


class GroupFilterObject(FilterObject):
    """ """
    def __init__(self, base_uri, tcl):
        """ """
        super(GroupFilterObject, self).__init__(base_uri, tcl)
        self._owners = []

        # define properties for resource type
        self._properties = GroupsProperties(base_uri=self.base_uri)
        self._resource_type = self._properties.resource_type

        # create default request object for filtered request with only owners
        self._request_object = RequestObject('groups', 'default')
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

    # special case for indicator associations
    def filter_associations(self, base_resource_type, identifier, group_type):
        """Get groups associated with base resource object
        GET /v2/groups/adversaries/747266/groups
        GET /v2/groups/adversaries/747266/groups/adversaries

        GET /v2/indicators/addresses/4.3.2.1/groups
        GET /v2/indicators/addresses/4.3.2.1/groups/adversaries

        GET /v2/victims/628/groups
        GET /v2/victims/628/groups/adversaries
        """
        base_properties = ResourceProperties[base_resource_type.name].value()

        request_uri = base_properties.base_path + '/'
        request_uri += str(identifier)
        if group_type is not None:
            group_properties = ResourceProperties[group_type.name].value()
            irt = group_properties.resource_type

            # update the request uri
            request_uri += '/' + group_properties.resource_uri_attribute
        else:
            request_uri += '/groups'
            irt = ResourceType.GROUPS

        description = 'Get group associations for {0} resource ({1}).'.format(
            base_resource_type.name.lower(), str(identifier))

        filter_type = 'group association'
        ro = RequestObject(
            filter_type, '{0}|{1}'.format(base_resource_type.name.lower(), identifier))
        ro.set_description(description)
        ro.set_owner_allowed(True)
        ro.set_resource_pagination(True)
        ro.set_request_uri(request_uri)
        ro.set_resource_type(irt)
        self._add_request_objects(ro)
