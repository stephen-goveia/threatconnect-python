""" standard """
import json
import urllib

""" custom """
import threatconnect.ResourceMethods
from threatconnect.Config.PropertiesAction import PropertiesAction
from threatconnect.DataFormatter import format_item, format_header
from threatconnect.ResourceMethods import *


def resource_class(dynamic_attribute_objs, resource_type):
    """
    This method will dynamically generate a ResourceObject class given
    an AttributeDef object. This method uses the passed object
    to dynamically build the Class with slots. Using slots *should*
    increase performance due to the large number of these objects being
    generated.
    """

    # predefined attributes
    attributes = (
        '_a_names',  # list of attribute name to use on __str__ output
        '_phase',  # action taken when working with api (read, add, update)
        '_association_objects',  # list of association objects for this resource
        '_association_requests',  # list of request object to add association
        '_attribute_objects',  # list of attributes objects for this resource
        '_attribute_requests',  # list of request object to add attributes
        '_data_methods',  # dictionary of resource attribute to processing method
        '_document',  # dictionary of resource attribute to processing method
        '_error_msgs',  # list of error messages
        '_json_data',  # the json data that forms the body
        '_methods',
        '_request_object',  # the request object for this resource
        '_request_url',  # request_urls that matched for this resource
        '_required_attrs',  # attributes required for an adding this resource
        '_resource_type',  # type of resource for this object
        '_security_labels_requests',  # list of security label requests for this resource
        '_tag_objects',  # list of tag objects for this resource
        '_tag_requests',  # list of tag requests for this resource
        '_validated',  # validation boolean for this resource
        '_writable_attrs')  # attributes that are writable for this resource

    attribute_list = set()
    for dao in dynamic_attribute_objs:
        attribute_list.add(dao.name)  # add_obj attr to tuple of attributes
        attribute_list.add(dao.method_get)
        attribute_list.add(dao.method_set)
        attribute_list.union(set(dao.extra_attributes))
        attribute_list.union(set(dao.extra_methods))

    attributes += tuple(attribute_list)
    del attribute_list

    class ResourceObject():
        __slots__ = attributes

        def __init__(self):
            self._a_names = []
            self._phase = None
            self._association_objects_groups = []
            self._association_objects_indicators = []
            self._association_objects_victim_assets = []
            self._association_objects_victims = []
            self._association_requests = []
            self._attribute_objects = []
            self._attribute_requests = []
            self._data_methods = {}
            self._document = None
            self._error_msgs = []
            self._json_data = {}
            self._methods = []
            self._request_object = None
            self._request_url = []
            self._required_attrs = []
            self._resource_type = resource_type
            self._security_label_requests = []
            self._tag_objects = []
            self._tag_requests = []
            self._validated = False
            self._writable_attrs = {}

            # add_obj name to 'a list' for __str__ method
            self.a_names('_phase')
            self.a_names('_error_msgs')
            self.a_names('_methods')
            self.a_names('_request_url')
            self.a_names('_required_attrs')
            self.a_names('_resource_object')
            self.a_names('_resource_type')
            self.a_names('_validated')
            self.a_names('_writable_attrs')

            for a_obj in dynamic_attribute_objs:
                # create the attribute with the default value
                setattr(self, a_obj.name, a_obj.type)

                # set extra attributes
                for aea in a_obj.extra_attributes:
                    setattr(self, aea, None)

                # add_obj required attribute to required list
                # if a_obj.required and action == PropertiesAction.POST:
                if a_obj.required:
                    self.add_required_attr(a_obj.name)

                # add_obj writable to writable list
                # if a_obj.writable and (action == PropertiesAction.POST or action == PropertiesAction.PUT):
                if a_obj.writable:
                    self.add_writable_attr(a_obj.api_names[0], a_obj.name)
                    self.add_method(a_obj.method_set)

                # add extra methods
                for aem in a_obj.extra_methods:
                    if not hasattr(self, aem):
                        extra_method = getattr(threatconnect.ResourceMethods, aem)
                        setattr(self, aem, types.MethodType(extra_method, self))
                        self.add_method(aem)

                # add_obj get method
                get_method = getattr(threatconnect.ResourceMethods, a_obj.method_get)
                setattr(self, a_obj.method_get, types.MethodType(get_method, self))

                # only add_obj get methods
                # if action == PropertiesAction.GET:
                self.add_method(a_obj.method_get)

                # add_obj set method
                set_method = getattr(threatconnect.ResourceMethods, a_obj.method_set)
                setattr(self, a_obj.method_set, types.MethodType(set_method, self))

                # only add_obj write methods
                # if action == PropertiesAction.POST and a_obj.writable:

                for api_name in a_obj.api_names:
                    self._data_methods[api_name] = getattr(self, a_obj.method_set)

                # add_obj attribute name to a_names list for __str__ method
                self.a_names(a_obj.name)

        def _associate(self, r_type, r_id, http_method, action):
            """
            # group to group
            POST /v2/groups/emails/747227/groups/adversaries/747266

            # group to indicator
            POST /v2/groups/incidents/119842/indicators/addresses/10.0.2.5
            POST /v2/groups/emails/747227/indicators/emailAddresses/bcs150@badguys.com

            # indicator to group
            POST /v2/indicators/addresses/10.0.2.5/groups/incidents/119842

            # group to victim
            POST /v2/groups/emails/747227/victims/628

            """

            #
            # get indicator type and properties
            #

            # get indicator properties for the object
            if r_type.value % 10:
                r_type = ResourceType(r_type.value - 5)
            rt_prop = threatconnect.Config.ResourceProperties.ResourceProperties[r_type.name].value()
            rt_uri = rt_prop.resource_uri_attribute

            # the pass in resource determines part of the url
            if 500 <= r_type.value <= 599:
                uri = 'indicators/' + rt_uri + '/' + str(r_id)
            elif 900 <= r_type.value <= 999:
                uri = 'victims' + '/' + str(r_id)
            else:
                uri = 'groups/' + rt_uri + '/' + str(r_id)

            # the identifier depend on the type of resource
            if 500 <= self.resource_type.value <= 599:
                identifier_method = self.get_indicator
            else:
                identifier_method = self.get_id

            #
            # prepare the request
            #

            # get properties for the object
            if self._resource_type.value % 10:
                self._resource_type = ResourceType(self._resource_type.value - 5)
            properties = threatconnect.Config.ResourceProperties.ResourceProperties[self._resource_type.name].value(
                http_method=http_method)

            description = action + ' association of ' + r_type.name.lower() + ' ('
            description += str(r_id) + ') with ' + self._resource_type.name.lower()
            description += ' resource id ({0}).'

            # build request object dict so that the identifier can be
            # pulled at the very end.  This is important due to using
            # temp ids when creating a resource.
            request_object_dict = {
                'name1': 'attribute',
                'name2_method': self.get_id,
                'description': description.encode('utf-8', 'ignore'),
                'http_method': properties.http_method,
                'request_uri_path': properties.association_add_path,
                'uri_attribute_1_method': identifier_method,
                'uri_attribute_2': uri,
                'owner_allowed': True,
                'resource_pagination': False,
                # TODO: what does this need to be?
                'resource_type': ResourceType.ATTRIBUTES}

            self.add_association_request(request_object_dict)

        def _security_label_mod(self, security_label, http_method, action):
            """ """
            # get properties for the object
            if self._resource_type.value % 10:
                self._resource_type = ResourceType(self._resource_type.value - 5)
            properties = threatconnect.Config.ResourceProperties.ResourceProperties[self._resource_type.name].value(
                http_method=http_method)

            # for indicators
            if 500 <= self._resource_type.value <= 599:
                # identifier = self.get_indicator()
                identifier_method = self.get_indicator
            else:
                # identifier = self.get_id()
                identifier_method = self.get_id

            description = action + ' the security label (' + security_label + ') on '
            description += self._resource_type.name.lower() + ' resource ({0}).'

            # build request object dict so that the identifier can be
            # pulled at the very end.  This is important due to using
            # temp ids when creating a resource.
            request_object_dict = {
                'name1': self._resource_type.name,
                'name2': security_label,
                'description': description.encode('utf-8', 'ignore'),
                'http_method': properties.http_method,
                'request_uri_path': properties.security_label_mod_path,
                'identifier_method': identifier_method,
                'security_label': security_label,
                'owner_allowed': True,
                'resource_pagination': False,
                'resource_type': ResourceType.SECURITY_LABELS}

            self.add_security_label_request(request_object_dict)

        def _tag_mod(self, tag, http_method, action):
            """ """
            # get properties for the object
            if self._resource_type.value % 10:
                self._resource_type = ResourceType(self._resource_type.value - 5)
            properties = threatconnect.Config.ResourceProperties.ResourceProperties[self._resource_type.name].value(
                http_method=http_method)

            # for indicators
            if 500 <= self._resource_type.value <= 599:
                # identifier = self.get_indicator()
                identifier_method = self.get_indicator
            else:
                # identifier = self.get_id()
                identifier_method = self.get_id

            description = action + ' the tag (' + tag + ') on '
            description += self._resource_type.name.lower() + ' resource ({0}).'

            # build request object dict so that the identifier can be
            # pulled at the very end.  This is important due to using
            # temp ids when creating a resource.
            request_object_dict = {
                'name1': self._resource_type.name,
                'name2': tag,
                'description': description.encode('utf-8', 'ignore'),
                'http_method': properties.http_method,
                'request_uri_path': properties.tag_mod_path,
                'identifier_method': identifier_method,
                'tag': tag,
                'owner_allowed': True,
                'resource_pagination': False,
                'resource_type': ResourceType.TAGS}

            self.add_tag_request(request_object_dict)

        def a_names(self, data):
            """ """
            self._a_names.append(data)

        def add(self):
            """ """
            self._phase = 'add'

        def add_association_group_object(self, data_obj):
            """ """
            self._association_objects_groups.append(data_obj)

        def add_association_indicator_object(self, data_obj):
            """ """
            self._association_objects_indicators.append(data_obj)

        def add_association_victim_object(self, data_obj):
            """ """
            self._association_objects_victims.append(data_obj)

        def add_association_victim_assets_object(self, data_obj):
            """ """
            self._association_objects_victim_assets.append(data_obj)

        def add_association_request(self, data_obj):
            """ """
            self._association_requests.append(data_obj)

        def add_attribute(self, attribute_type, value, displayed=True):
            """ """
            body_json = json.dumps({
                'type': attribute_type,
                'value': value,
                'displayed': displayed})

            # get properties for the object
            if self._resource_type.value % 10:
                self._resource_type = ResourceType(self._resource_type.value - 5)
            properties = threatconnect.Config.ResourceProperties.ResourceProperties[self._resource_type.name].value(
                http_method=PropertiesAction.POST)

            # special case for indicators
            if 500 <= self._resource_type.value <= 599:
                identifier_method = self.get_indicator
            else:
                identifier_method = self.get_id

            description = 'Adding attribute type (' + attribute_type + ') with value of ('
            description += value + ') on ' + self._resource_type.name.lower() + ' resource ({0}).'

            # build request object dict so that the identifier can be
            # pulled at the very end.  This is important due to using
            # temp ids when creating a resource.
            request_object_dict = {
                'name1': 'attribute',
                'name2': '{0}|{1}'.format(attribute_type, value),
                'body': body_json,
                'description': description.decode('utf-8', 'ignore'),
                # 'description': unicode(description, errors='ignore'),
                'http_method': properties.http_method,
                'request_uri_path': properties.attribute_add_path,
                'identifier_method': identifier_method,
                'owner_allowed': True,
                'resource_pagination': False,
                'resource_type': ResourceType.ATTRIBUTES}

            self.add_attribute_request(request_object_dict)

        def add_attribute_object(self, data_obj):
            """ """
            self._attribute_objects.append(data_obj)

        def add_attribute_request(self, data_obj):
            """ """
            self._attribute_requests.append(data_obj)

        def add_error_msg(self, data):
            """ """
            self._error_msgs.append(data)

        def add_method(self, data):
            """ """
            self._methods.append(data)

        def add_request_url(self, data):
            """ """
            if data not in self._request_url:
                self._request_url.append(data)

        def add_required_attr(self, data):
            """ """
            self._required_attrs.append(data)

        def add_security_label(self, security_label):
            """ """
            self._security_label_mod(security_label, PropertiesAction.POST, 'Adding')

        def add_tag(self, tag):
            """ """
            self._tag_mod(tag, PropertiesAction.POST, 'Adding')

        def add_tag_object(self, data_obj):
            """ """
            self._tag_objects.append(data_obj)

        def add_security_label_request(self, data_obj):
            """ """
            self._security_label_requests.append(data_obj)

        def add_tag_request(self, data_obj):
            """ """
            self._tag_requests.append(data_obj)

        def add_writable_attr(self, data_key, data_val):
            """ """
            self._writable_attrs[data_key] = data_val

        def associate(self, r_type, r_id):
            """ """
            self._associate(r_type, r_id, PropertiesAction.POST, 'Adding')

        def clear_association_objects_groups(self):
            """ """
            self._association_objects_groups = []

        def clear_association_objects_indicators(self):
            """ """
            self._association_objects_indicators = []

        def clear_attribute_objects(self):
            """ """
            self._attribute_objects = []

        def clear_tag_objects(self):
            """ """
            self._tag_objects = []

        def delete(self):
            """ """
            self._phase = 'delete'

        def delete_attribute(self, attribute_id):
            """ """
            # get properties for the object
            if self._resource_type.value % 10:
                self._resource_type = ResourceType(self._resource_type.value - 5)
            properties = threatconnect.Config.ResourceProperties.ResourceProperties[self._resource_type.name].value(
                http_method=PropertiesAction.DELETE)

            # special case for indicators
            if 500 <= resource_type.value <= 599:
                identifier_method = self.get_indicator
                owner_allowed = True
            else:
                identifier_method = self.get_id
                owner_allowed = False

            description = 'Deleting attribute id (' + str(attribute_id) + ') from '
            description += self._resource_type.name.lower() + ' resource ({0}).'

            # build request object dict so that the identifier can be
            # pulled at the very end.  This is important due to using
            # temp ids when creating a resource.
            request_object_dict = {
                'name1': 'attribute',
                'name2': attribute_id,
                'description': description.encode('utf-8', 'ignore'),
                'http_method': properties.http_method,
                'request_uri_path': properties.attribute_delete_path,
                'identifier_method': identifier_method,
                'attribute_id': attribute_id,
                'owner_allowed': owner_allowed,
                'resource_pagination': False,
                'resource_type': ResourceType.ATTRIBUTES}

            self.add_attribute_request(request_object_dict)

        def delete_tag(self, tag):
            """ """
            self._tag_mod(tag, PropertiesAction.DELETE, 'Deleting')

        def disassociate(self, r_type, r_id):
            """ """
            self._associate(r_type, r_id, PropertiesAction.DELETE, 'Deleting')

        def get_data_methods(self):
            """ """
            return self._data_methods

        def get_error(self):
            """ """
            if len(self._error_msgs) > 0:
                return True
            else:
                return False

        def get_error_msgs(self):
            """ """
            return self._error_msgs

        def get_json(self):
            """ """
            json_data = {}
            for key, val in self._writable_attrs.viewitems():
                key_attr = '_{0}'.format(key)
                if hasattr(self, key_attr):
                    # file hash
                    data_val = getattr(self, key_attr)
                else:
                    data_val = getattr(self, val)
                # add data to json output
                if data_val is not None:
                    json_data[key] = data_val
            return json.dumps(json_data)

        def get_methods(self):
            """ """
            return sorted(self._methods)

        def get_request_url(self):
            """ """
            return self._request_url

        def get_required_attrs(self):
            """ """
            return self._required_attrs

        def get_writable_attrs(self):
            """ """
            return self._writable_attrs

        def set_phase(self, data):
            """ """
            self._phase = data

        def set_document(self, data):
            """ """
            self._document = data

        def set_request_object(self, data_obj):
            """ """
            self._request_object = data_obj

        def update_attribute(self, attribute_id, value):
            """ """
            body_json = json.dumps({
                'value': value})

            # get properties for the object
            if self._resource_type.value % 10:
                self._resource_type = ResourceType(self._resource_type.value - 5)
            properties = threatconnect.Config.ResourceProperties.ResourceProperties[self._resource_type.name].value(
                http_method=PropertiesAction.PUT)

            # special case for indicators
            if 500 <= resource_type.value <= 599:
                identifier_method = self.get_indicator
                owner_allowed = True
            else:
                identifier_method = self.get_id
                owner_allowed = False

            description = 'Updating attribute id (' + str(attribute_id) + ') with value of ('
            description += value + ') on ' + self._resource_type.name.lower() + ' resource ({0}).'

            # build request object dict so that the identifier can be
            # pulled at the very end.  This is important due to using
            # temp ids when creating a resource.
            request_object_dict = {
                'name1': 'attribute',
                'name2': '{0}|{1}'.format(attribute_id, value),
                'body': body_json,
                'description': description.encode('utf-8', 'ignore'),
                'http_method': properties.http_method,
                'request_uri_path': properties.attribute_update_path,
                'identifier_method': identifier_method,
                'attribute_id': attribute_id,
                'owner_allowed': owner_allowed,
                'resource_pagination': False,
                'resource_type': ResourceType.ATTRIBUTES}

            self.add_attribute_request(request_object_dict)

        @property
        def phase(self):
            """ """
            return self._phase

        @property
        def association_objects_groups(self):
            """ """
            return self._association_objects_groups

        @property
        def association_objects_indicators(self):
            """ """
            return self._association_objects_indicators

        @property
        def association_objects_victims(self):
            """ """
            return self._association_objects_victims

        @property
        def association_objects_victim_assets(self):
            """ """
            return self._association_objects_victim_assets

        @property
        def association_requests(self):
            """ """
            for rod in self._association_requests:
                # build request object
                request_object = RequestObject(rod['name1'], rod['name2_method']())
                request_object.set_description(rod['description'].format(rod['uri_attribute_1_method']()))
                request_object.set_http_method(rod['http_method'])
                request_object.set_request_uri(
                    rod['request_uri_path'].format(
                        rod['uri_attribute_1_method'](),
                        rod['uri_attribute_2']))
                request_object.set_owner_allowed(rod['owner_allowed'])
                request_object.set_resource_pagination(rod['resource_pagination'])
                request_object.set_resource_type(rod['resource_type'])

                yield request_object

        @property
        def attribute_objects(self):
            """ """
            return self._attribute_objects

        @property
        def attribute_requests(self):
            """ """
            for rod in self._attribute_requests:
                # build request object
                request_object = RequestObject(rod['name1'], rod['name2'])
                # request_object.set_description(rod['description'].format(rod['identifier_method']()))
                request_object.set_description('temp')
                request_object.set_http_method(rod['http_method'])
                identifier = rod['identifier_method']()
                if self._resource_type in [ResourceType.URL, ResourceType.URLS]:
                    identifier = urllib.quote(identifier, safe='~')
                # body only exist on POST and PUT
                if rod['http_method'] in ['POST', 'PUT']:
                    request_object.set_body(rod['body'])
                # uri is different depending on the http method
                if rod['http_method'] == 'POST':
                    request_object.set_request_uri(
                        rod['request_uri_path'].format(identifier))
                elif rod['http_method'] in ['DELETE', 'PUT']:
                    request_object.set_request_uri(
                        rod['request_uri_path'].format(
                            identifier, rod['attribute_id']))
                request_object.set_owner_allowed(rod['owner_allowed'])
                request_object.set_resource_pagination(rod['resource_pagination'])
                request_object.set_resource_type(rod['resource_type'])

                yield request_object

        @property
        def document(self):
            """ """
            return self._document

        @property
        def request_object(self):
            """ """
            return self._request_object

        @property
        def resource_type(self):
            """ """
            return self._resource_type

        @property
        def security_label_requests(self):
            """ """
            for rod in self._security_label_requests:
                # build request object
                request_object = RequestObject(rod['name1'], rod['name2'])
                request_object.set_description(rod['description'].format(rod['identifier_method']()))
                request_object.set_http_method(rod['http_method'])
                identifier = rod['identifier_method']()
                if self._resource_type in [ResourceType.URL, ResourceType.URLS]:
                    identifier = urllib.quote(identifier, safe='~')
                request_object.set_request_uri(
                    rod['request_uri_path'].format(identifier, rod['security_label']))
                request_object.set_owner_allowed(rod['owner_allowed'])
                request_object.set_resource_pagination(rod['resource_pagination'])
                request_object.set_resource_type(rod['resource_type'])

                yield request_object

        @property
        def tag_objects(self):
            """ """
            return self._tag_objects

        @property
        def tag_requests(self):
            """ """
            for rod in self._tag_requests:
                # build request object
                request_object = RequestObject(rod['name1'], rod['name2'])
                request_object.set_description(rod['description'].format(rod['identifier_method']()))
                request_object.set_http_method(rod['http_method'])
                identifier = rod['identifier_method']()
                if self._resource_type in [ResourceType.URL, ResourceType.URLS]:
                    identifier = urllib.quote(identifier, safe='~')
                request_object.set_request_uri(
                    rod['request_uri_path'].format(identifier, rod['tag']))
                request_object.set_owner_allowed(rod['owner_allowed'])
                request_object.set_resource_pagination(rod['resource_pagination'])
                request_object.set_resource_type(rod['resource_type'])

                yield request_object

        def validate(self):
            """ """
            if len(self._error_msgs) > 0:
                return False

            for required in self._required_attrs:
                val = getattr(self, required)

                if val is None:
                    # fail if any required attribute is None
                    return False
                elif isinstance(val, list):
                    if not val:
                        # fail if any required attribute list is empty
                        return False

            self._validated = True
            return self._validated

        def __str__(self):
            """allow object to be displayed with print"""
            printable_items = dict(self.__dict__)
            if hasattr(self, 'get_indicator'):
                obj_str = format_header(
                    '{0} ({1})'.format(self.get_indicator(), self.resource_type.name.lower()))
                printable_items.pop('_indicator')
            elif hasattr(self, 'get_name'):
                obj_str = format_header(
                    '{0} ({1})'.format(self.get_name(), self.resource_type.name.lower()))
                printable_items.pop('_name')
            elif hasattr(self, 'get_id'):
                obj_str = format_header(
                    '{0} ({1})'.format(self.get_id(), self.resource_type.name.lower()))
                printable_items.pop('_id')
            else:
                obj_str = format_header('ResourceObject')

            for key, val in sorted(printable_items.viewitems()):
                if key in self._a_names:
                    obj_str += format_item(key, val)

            return obj_str

    return ResourceObject
