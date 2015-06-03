""" custom """
from threatconnect import ResourceMethods
from threatconnect.Config.PropertiesAction import PropertiesAction
from threatconnect.Config.ResourceUri import ResourceUri
from threatconnect.Properties.Properties import Properties
from threatconnect.ResourceObject import resource_class


class IndicatorProperties(Properties):
    """ """

    def __init__(self, base_uri='v2', http_method=PropertiesAction.GET):
        """ """
        super(IndicatorProperties, self).__init__(base_uri, http_method)
        self._http_method = http_method

        self._object_attributes = [
            ResourceMethods.confidence_attr,
            ResourceMethods.date_added_attr,
            ResourceMethods.description_attr,
            ResourceMethods.id_attr,
            ResourceMethods.last_modified_attr,
            ResourceMethods.owner_name_attr,
            ResourceMethods.matched_filters_attr,
            ResourceMethods.rating_attr,
            ResourceMethods.summary_attr,
            ResourceMethods.type_attr,
            ResourceMethods.web_link_attr,
        ]

    @property
    def association_add_path(self):
        """ """
        return ResourceUri.INDICATORS.value + '/' + self.resource_uri_attribute + '/{0}/{1}'

    @property
    def association_group_path(self):
        """ """
        return ResourceUri.INDICATORS.value + '/' + self.resource_uri_attribute + '/{0}/groups'

    @property
    def association_indicator_path(self):
        """ """
        return ResourceUri.INDICATORS.value + '/' + self.resource_uri_attribute + '/{0}/indicators'

    @property
    def association_victim_path(self):
        """ """
        return ResourceUri.INDICATORS.value + '/' + self.resource_uri_attribute + '/{0}/victims'

    @property
    def attribute_path(self):
        """ """
        return ResourceUri.INDICATORS.value + '/' + self.resource_uri_attribute + '/{0}/attributes'

    @property
    def attribute_add_path(self):
        """ """
        return ResourceUri.INDICATORS.value + '/' + self.resource_uri_attribute + '/{0}/attributes'

    @property
    def attribute_update_path(self):
        """ """
        return ResourceUri.INDICATORS.value + '/' + self.resource_uri_attribute + '/{0}/attributes/{1}'

    @property
    def attribute_delete_path(self):
        """ """
        return ResourceUri.INDICATORS.value + '/' + self.resource_uri_attribute + '/{0}/attributes/{1}'

    @property
    def base_path(self):
        """ """
        return '/' + self._base_uri + '/indicators/' + self._resource_uri_attribute

    @property
    def delete_path(self):
        """ """
        return ResourceUri.INDICATORS.value + '/' + self._resource_uri_attribute + '/{0}'

    @property
    def post_path(self):
        """ """
        return ResourceUri.INDICATORS.value + '/' + self._resource_uri_attribute

    @property
    def put_path(self):
        """ """
        return ResourceUri.INDICATORS.value + '/{0}/{1}'

    @property
    def resource_object(self):
        return resource_class(self._object_attributes, self._resource_type)()

    @property
    def security_label_add_path(self):
        """ """
        return ResourceUri.INDICATORS.value + '/' + self.resource_uri_attribute + '/{0}/securityLabels/{1}'

    @property
    def security_label_mod_path(self):
        """ """
        return ResourceUri.INDICATORS.value + '/' + self.resource_uri_attribute + '/{0}/securityLabels/{1}'

    @property
    def tag_add_path(self):
        """ """
        return ResourceUri.INDICATORS.value + '/' + self.resource_uri_attribute + '/{0}/tags/{1}'

    @property
    def tag_mod_path(self):
        """ """
        return ResourceUri.INDICATORS.value + '/' + self.resource_uri_attribute + '/{0}/tags/{1}'

    @property
    def tag_delete_path(self):
        """ """
        return ResourceUri.INDICATORS.value + '/' + self.resource_uri_attribute + '/{0}/tags/{1}'

    @property
    def tag_path(self):
        """ """
        # /v2/indicators/<indicator type>/<value>/tags
        return ResourceUri.INDICATORS.value + '/' + self.resource_uri_attribute + '/{0}/tags'
