""" custom """
from threatconnect import ResourceMethods
from threatconnect.Config.PropertiesAction import PropertiesAction
from threatconnect.Config.ResourceType import ResourceType
from threatconnect.Config.ResourceUri import ResourceUri
from threatconnect.Properties.Properties import Properties
from threatconnect.ResourceObject import resource_class


class OwnersProperties(Properties):
    """
    URIs:
    /v2/owners
    /v2/indicators/<indicator type>/<value>/owners

    JSON Data:
    {"id" : 640,
     "name" : "Demo Customer Community",
     "type" : "Community"
    }
    """

    def __init__(self, base_uri='v2', http_method=PropertiesAction.GET):
        """
        /<api version>/owners
        /<api version>/indicators/<indicator type>/<value>/owners
        """
        super(OwnersProperties, self).__init__(base_uri, http_method)
        self._http_method = http_method

        # resource properties
        self._resource_key = 'owner'
        self._resource_pagination = False
        self._resource_type = ResourceType.OWNERS
        self._resource_uri_attribute = 'owners'

        self._object_attributes = [
            ResourceMethods.id_attr,
            ResourceMethods.matched_filters_attr,
            ResourceMethods.name_attr,
            ResourceMethods.type_attr]

    @property
    def base_owner_allowed(self):
        """ """
        return False

    @property
    def base_path(self):
        """ """
        return ResourceUri.OWNERS.value

    @property
    def filters(self):
        """ """
        # TODO: get_owners is a quick hack and needs to be fixed
        return ['add_indicator',
                'get_owners']

    @property
    def indicator_owner_allowed(self):
        return False

    @property
    def indicator_path(self):
        return ResourceUri.INDICATORS.value + '/{0}/{1}/' + self._resource_uri_attribute

    @property
    def resource_object(self):
        return resource_class(self._object_attributes, self._resource_type)()

