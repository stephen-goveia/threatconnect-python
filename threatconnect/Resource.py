""" standard """
import dateutil.parser
import sys
import time
import urllib
import uuid

""" custom """
from threatconnect.ErrorCodes import ErrorCodes
from threatconnect.Config.FilterOperator import FilterOperator
from threatconnect.Config.PropertiesAction import PropertiesAction
from threatconnect.Config.PropertiesEnums import ApiStatus
from threatconnect.Config.ResourceProperties import ResourceProperties
from threatconnect.Config.ResourceType import ResourceType
from threatconnect.DataFormatter import (format_header, format_item)
from threatconnect.Properties.GroupProperties import GroupProperties
from threatconnect.Properties.IndicatorProperties import IndicatorProperties
from threatconnect.RequestObject import RequestObject
from threatconnect.Validate import get_resource_type


class Resource(object):
    """ """

    def __init__(self, tc_obj):
        """ """
        # instance of the ThreatConnect object
        self._tc = tc_obj
        self.base_uri = self._tc.base_uri
        self.tcl = self._tc.tcl

        # filtered resource object list
        self._objects = []
        self._objects_dict = {}

        # master resource object list
        self._master_objects = []

        # filtered resource indexes
        self._object_res_id_idx = {}
        self._object_res_name_idx = {}

        # master resource indexes
        self._master_res_id_idx = {}
        self._master_object_id_idx = {}

        # Post Filter Indexes
        self._attribute_idx = {}
        self._confidence_idx = {}
        self._date_added_idx = {}
        self._file_type_idx = {}
        self._last_modified_idx = {}
        self._name_idx = {}
        self._rating_idx = {}
        self._threat_assess_confidence_idx = {}
        self._threat_assess_rating_idx = {}
        self._tag_idx = {}
        self._type_idx = {}

        # defaults
        self._api_response = []
        self._current_filter = None
        self._error = False
        self._error_messages = []
        self._filter_class = None
        self._filter_objects = []
        self._http_method = None
        self._max_results = None
        self._method = None
        self._object_class = None
        self._owners = []
        self._owner_allowed = False
        self._request_object = None
        self._request_uri = None
        self._resource_object = None
        self._resource_pagination = False
        self._resource_type = None
        self._result_count = 0
        self._status = ApiStatus.SUCCESS
        self._status_code = []
        self._uris = []

    def add(self, resource_name):
        """add resource using writable api"""
        # switch any multiple resource request to single result request
        if self._resource_type.value % 10:
            self._resource_type = ResourceType(self._resource_type.value - 5)
        # get properties for the object
        properties = ResourceProperties[self._resource_type.name].value(
            base_uri=self._tc.base_uri, http_method=PropertiesAction.POST)

        # generate unique temporary id
        resource_id = uuid.uuid4().int

        # resource object
        resource_object = properties.resource_object
        # set resource id
        resource_object.set_id(resource_id)
        # set resource name
        resource_object.set_name(resource_name)
        # set resource api action
        resource_object.set_phase('add')

        # build request object
        request_object = RequestObject(self._resource_type.name, resource_id)
        request_object.set_description(
            'Adding {0} resource ({1})'.format(self._resource_type.name.lower(), resource_name))
        request_object.set_http_method(properties.http_method)
        request_object.set_request_uri(properties.post_path)
        request_object.set_owner_allowed(True)
        request_object.set_resource_pagination(False)
        request_object.set_resource_type(self._resource_type)

        # add to temporary object storage
        self.add_master_resource_obj(resource_object, resource_id)
        res = self.get_resource_by_id(resource_id)
        request_object.set_resource_object_id(id(res))
        res.set_request_object(request_object)

        # add resource object to parent object
        self.add_obj(res)

        # return object for modification
        return res

    def add_obj(self, data_obj):
        """add object to resource instance"""
        has_id = False

        # update id index
        if hasattr(data_obj, 'get_id'):
            resource_id = data_obj.get_id()
            if resource_id is not None:
                # signify that id will be used a index key
                has_id = True
                if resource_id not in self._object_res_id_idx:
                    self._object_res_id_idx.setdefault(resource_id, data_obj)
                    self._objects.append(data_obj)
                    self._objects_dict.setdefault(id(data_obj), data_obj)

        # use name if id is not available
        if hasattr(data_obj, 'get_name'):
            resource_name = data_obj.get_name()
            if resource_name is not None:
                if resource_name not in self._object_res_name_idx:
                    self._object_res_name_idx.setdefault(resource_name, []).append(data_obj)

                    # only do this if the object has no id
                    if not has_id:
                        self._objects.append(data_obj)

    def add_api_response(self, data):
        """ """
        self._api_response.append(data)

    def add_error_message(self, data):
        """ """
        self.tcl.error(data)
        self._error_messages.append(data)

    def add_filter(self, resource_type=None):
        if resource_type is not None:
            filter_obj = self._filter_class(self.base_uri, self.tcl, resource_type)
        else:
            filter_obj = self._filter_class(self.base_uri, self.tcl)

        # append filter object
        self._filter_objects.append(filter_obj)

        return filter_obj

    def add_owners(self, data):
        """ """
        if isinstance(data, list):
            self._owners.extend(data)
        else:
            self._owners.append(data)

    def get_errors(self):
        """ """
        return self._error_messages

    def get_group_associations(self, resource_obj, group_type=None):
        """
        GET /v2/groups/adversaries/747266/groups
        GET /v2/groups/adversaries/747266/groups/adversaries
        """
        resource_obj.clear_association_objects_groups()

        # for indicators
        if 500 <= self._resource_type.value <= 599:
            identifier = resource_obj.get_indicator()
        else:
            identifier = resource_obj.get_id()

        groups = self._tc.groups()
        filter1 = groups.add_filter()
        filter1.add_owner([resource_obj.get_owner_name()])
        filter1.filter_associations(resource_obj.resource_type, identifier, group_type)
        groups.retrieve()

        for obj in groups:
            resource_obj.add_association_group_object(obj)
        del groups

    def get_indicator_associations(self, resource_obj, indicator_type=None):
        """
        GET /v2/groups/adversaries/747266/indicators
        GET /v2/groups/adversaries/747266/indicators/addresses
        """
        resource_obj.clear_association_objects_indicators()

        # for indicators
        if 500 <= self._resource_type.value <= 599:
            identifier = resource_obj.get_indicator()
        else:
            identifier = resource_obj.get_id()

        indicators = self._tc.indicators()
        filter1 = indicators.add_filter()
        filter1.add_owner([resource_obj.get_owner_name()])
        filter1.filter_associations(resource_obj.resource_type, identifier, indicator_type)
        indicators.retrieve()

        for obj in indicators:
            resource_obj.add_association_indicator_object(obj)
        del indicators

    def get_victim_associations(self, resource_obj):
        """
        GET /v2/groups/emails/747227/victims

        GET /v2/groups/emails/747227/victimAssets
        GET /v2/groups/emails/747227/victimAssets/emailAddresses
        """
        # for indicators
        if 500 <= self._resource_type.value <= 599:
            identifier = resource_obj.get_indicator()
        else:
            identifier = resource_obj.get_id()

        victims = self._tc.victims()
        filter1 = victims.add_filter()
        filter1.filter_associations(resource_obj.resource_type, identifier)
        victims.retrieve()

        for obj in victims:
            resource_obj.add_association_victim_object(obj)
        del victims

    def get_attributes(self, resource_obj):
        """ """
        resource_obj.clear_attribute_objects()

        resource_type = resource_obj.request_object.resource_type

        # special case for indicators
        if 500 <= resource_type.value <= 599:
            resource_type = get_resource_type(resource_obj.get_indicator())

        # switch any multiple resource request to single result request
        if resource_type.value % 10:
            resource_type = ResourceType(resource_type.value - 5)
        # get properties for the object
        properties = ResourceProperties[resource_type.name].value()

        # build request object
        if isinstance(properties, IndicatorProperties):
            # indicator resource

            # switch any multiple resource request to single result request
            if resource_type.value % 10:
                resource_type = ResourceType(resource_type.value - 5)
            # get properties for the object
            properties = ResourceProperties[resource_type.name].value()

            request_object = RequestObject(resource_type.name, resource_obj.get_indicator())
            request_object.set_http_method(properties.http_method)
            indicator = resource_obj.get_indicator()
            if resource_type in [ResourceType.URL, ResourceType.URLS]:
                indicator = urllib.quote(indicator, safe='~')
            request_object.set_request_uri(properties.attribute_path.format(indicator))
            request_object.set_owner_allowed(True)
            request_object.set_resource_pagination(True)
            request_object.set_resource_type(ResourceType.ATTRIBUTES)
        elif isinstance(properties, GroupProperties):
            request_object = RequestObject(resource_type.name, resource_obj.get_id())
            request_object.set_http_method(properties.http_method)
            request_object.set_request_uri(properties.attribute_path.format(resource_obj.get_id()))
            request_object.set_owner_allowed(False)
            request_object.set_resource_pagination(True)
            request_object.set_resource_type(ResourceType.ATTRIBUTES)
        else:
            request_object = None

        attributes = self._tc.attributes()
        data_set = self._tc.api_build_request(attributes, request_object, [resource_obj.get_owner_name()])

        for obj in data_set:
            resource_obj.add_attribute_object(obj)

    def get_signature(self, resource_obj):
        """ """
        # resource_obj.clear_signature()

        resource_type = resource_obj.request_object.resource_type

        # switch any multiple resource request to single result request
        if resource_type.value % 10:
            resource_type = ResourceType(resource_type.value - 5)

        if resource_type == ResourceType.SIGNATURE:
            properties = ResourceProperties[resource_type.name].value()

            request_object = RequestObject(resource_type.name, resource_obj.get_id())
            request_object.set_http_method(properties.http_method)
            request_object.set_request_uri(properties.download_path.format(resource_obj.get_id()))
            request_object.set_owner_allowed(False)
            request_object.set_resource_pagination(False)
            request_object.set_resource_type(ResourceType.SIGNATURE)

            signatures = self._tc.signatures()
            signature = self._tc.api_build_request(signatures, request_object, resource_obj.get_owner_name())
            resource_obj.set_file_text(signature)
            del signatures

    def get_resource_by_identity(self, data):
        if data in self._master_object_id_idx:
            return self._master_object_id_idx[data]

    def add_master_resource_obj(self, data_obj, index):
        """ """
        resource_object_id = id(data_obj)
        # has_id = False
        duplicate = True

        # update master resource object id index
        self._master_object_id_idx.setdefault(id(data_obj), data_obj)

        if index not in self._master_res_id_idx:
            self._master_objects.append(data_obj)
            self._master_res_id_idx.setdefault(index, data_obj)
            duplicate = False
        else:
            resource_object_id = id(self._master_res_id_idx[index])

        #
        # post filters indexes
        #
        if not duplicate:
            #
            # confidence index
            #
            if hasattr(data_obj, 'get_confidence'):
                if data_obj.get_confidence() is not None:
                    self._confidence_idx.setdefault(
                        data_obj.get_confidence(), []).append(data_obj)

            #
            # date added index
            #
            if hasattr(data_obj, 'get_date_added'):
                if data_obj.get_date_added() is not None:
                    date_added = data_obj.get_date_added()
                    date_added = dateutil.parser.parse(date_added)
                    date_added_seconds = int(time.mktime(date_added.timetuple()))
                    self._date_added_idx.setdefault(date_added_seconds, []).append(data_obj)

            #
            # file type index
            #
            if hasattr(data_obj, 'get_file_type'):
                if data_obj.get_file_type() is not None:
                    self._file_type_idx.setdefault(data_obj.get_file_type(), []).append(data_obj)

            #
            # last modified index
            #
            if hasattr(data_obj, 'get_last_modified'):
                if data_obj.get_last_modified() is not None:
                    last_modified = data_obj.get_last_modified()
                    last_modified = dateutil.parser.parse(last_modified)
                    last_modified_seconds = int(time.mktime(last_modified.timetuple()))
                    self._last_modified_idx.setdefault(last_modified_seconds, []).append(data_obj)

            #
            # name index
            #
            if hasattr(data_obj, 'get_name'):
                if data_obj.get_name() is not None:
                    self._name_idx.setdefault(
                        data_obj.get_name(), []).append(data_obj)

            #
            # rating index
            #
            if hasattr(data_obj, 'get_rating'):
                if data_obj.get_rating() is not None:
                    self._rating_idx.setdefault(
                        data_obj.get_rating(), []).append(data_obj)

            #
            # threat assess confidence index
            #
            if hasattr(data_obj, 'get_threat_assess_confidence'):
                if data_obj.get_threat_assess_confidence() is not None:
                    self._threat_assess_confidence_idx.setdefault(
                        data_obj.get_threat_assess_confidence(), []).append(data_obj)

            #
            # threat assess rating index
            #
            if hasattr(data_obj, 'get_threat_assess_rating'):
                if data_obj.get_threat_assess_rating() is not None:
                    self._threat_assess_rating_idx.setdefault(
                        data_obj.get_threat_assess_rating(), []).append(data_obj)

            #
            # type index
            #
            if hasattr(data_obj, 'get_type'):
                if data_obj.get_type() is not None:
                    self._type_idx.setdefault(data_obj.get_type(), []).append(data_obj)

            #
            # attributes (nested object)
            #
            if len(data_obj.attribute_objects) > 0:
                for attribute_obj in data_obj.attribute_objects:
                    self._attribute_idx.setdefault(
                        attribute_obj.get_type(), []).append(data_obj)

            #
            # tags (nested object)
            #
            if len(data_obj.tag_objects) > 0:
                for tag_obj in data_obj.tag_objects:
                    self._tag_idx.setdefault(
                        tag_obj.get_name(), []).append(data_obj)

        return resource_object_id

    def add_result_count(self, data_int):
        """ """
        self._result_count += data_int

    def add_status(self, data_enum):
        """ """
        self._status = ApiStatus(self._status.value & data_enum.value)

    def add_status_code(self, data_int):
        """ """
        self._status_code.append(data_int)

    def add_uris(self, data):
        """ """
        self._uris.append(data)

    def commit(self, owners=None):
        """ """
        self.tcl.debug('committing')
        # iterate through each object in COPY of resource objects
        for obj in list(self._objects):

            # TODO: Test this logic
            # continue to next object if already processed
            if obj.phase in ['added', 'updated']:
                self.tcl.info('skipping already processed object: {0}'.format(obj.phase))
                continue

            self.tcl.debug('phase: {0}'.format(obj.phase))

            temporary_id = None
            new_id = None

            # BCS - is there a reason to use the resource type in the request object?
            # resource_type = obj.request_object.resource_type
            resource_type = obj.resource_type

            # special case for indicators
            if 500 <= resource_type.value <= 599:
                resource_type = get_resource_type(obj.get_indicator())

            # the body needs to be set right before the commit
            if obj.phase == 'add':
                self.tcl.debug('add')
                if obj.validate():
                    temporary_id = str(obj.get_id())
                    # add resource
                    obj.request_object.set_body(obj.get_json())
                    self._tc.api_build_request(self, obj.request_object, owners)
                    new_id = str(obj.get_id())

                    obj.set_phase('added')
                else:
                    print('Failed validation.')
                    print(obj)
            elif obj.phase == 'update':
                # switch any multiple resource request to single result request
                if resource_type.value % 10:
                    resource_type = ResourceType(resource_type.value - 5)
                properties = ResourceProperties[resource_type.name].value(
                    base_uri=self._tc.base_uri, http_method=PropertiesAction.PUT)

                if isinstance(properties, IndicatorProperties):
                    # request object for groups
                    request_object = RequestObject(resource_type.name, obj.get_indicator())
                    request_object.set_description(
                        'Update {0} indicator ({1}).'.format(
                            self._resource_type.name.lower(), obj.get_indicator()))
                    request_object.set_body(obj.get_json())
                    request_object.set_http_method(properties.http_method)
                    request_object.set_request_uri(
                        properties.put_path.format(
                            properties.resource_uri_attribute, obj.get_indicator()))
                    request_object.set_owner_allowed(True)
                    request_object.set_resource_pagination(False)
                    request_object.set_resource_type(resource_type)

                elif isinstance(properties, GroupProperties):
                    # request object for groups
                    request_object = RequestObject(resource_type.name, obj.get_id())
                    request_object.set_description(
                        'Update {0} resource object with id ({1}).'.format(
                            self._resource_type.name.lower(), obj.get_id()))
                    request_object.set_body(obj.get_json())
                    request_object.set_http_method(properties.http_method)
                    request_object.set_request_uri(properties.put_path.format(obj.get_id()))
                    request_object.set_owner_allowed(False)
                    request_object.set_resource_pagination(False)
                    request_object.set_resource_type(resource_type)

                # update resource
                self._tc.api_build_request(self, request_object, owners)
                obj.set_phase('updated')

            elif obj.phase == 'delete':
                # switch any multiple resource request to single result request
                if resource_type.value % 10:
                    resource_type = ResourceType(resource_type.value - 5)
                properties = ResourceProperties[resource_type.name].value(
                    base_uri=self._tc.base_uri, http_method=PropertiesAction.DELETE)

                if isinstance(properties, IndicatorProperties):
                    request_object = RequestObject(resource_type.name, obj.get_indicator())
                    request_object.set_description(
                        'Deleting {0} indicator resource ({1}).'.format(
                            resource_type.name.lower(), obj.get_indicator()))
                    request_object.set_http_method(properties.http_method)
                    request_object.set_request_uri(
                        properties.delete_path.format(obj.get_indicator()))
                    request_object.set_owner_allowed(True)
                    request_object.set_resource_pagination(False)
                    request_object.set_resource_type(resource_type)
                elif isinstance(properties, GroupProperties):
                    request_object = RequestObject(resource_type.name, obj.get_id())
                    request_object.set_description(
                        'Deleting {0} resource object with id ({1}).'.format(
                            resource_type.name.lower(), obj.get_id()))
                    request_object.set_http_method(properties.http_method)
                    request_object.set_request_uri(properties.delete_path.format(obj.get_id()))
                    request_object.set_owner_allowed(True)
                    request_object.set_resource_pagination(False)
                    request_object.set_resource_type(resource_type)

                self._tc.api_build_request(self, request_object, owners)
                self._objects.remove(obj)

            """
            Process all nested associations, attributes, tags and upload/download
            """

            #
            # process attribute requests
            #
            for request_object in obj.attribute_requests:
                if request_object.http_method in ['DELETE', 'POST', 'PUT']:
                    # instantiate attribute resource object
                    attributes = self._tc.attributes()
                    self._tc.api_build_request(attributes, request_object, owners)

                    del attributes
                    # self.get_attributes(obj)

            #
            # process tag requests
            #
            for request_object in obj.tag_requests:
                # replace temporary id
                if temporary_id != new_id:
                    request_uri = str(request_object.request_uri.encode("utf-8")).replace(temporary_id, new_id)
                    request_object.set_request_uri(request_uri)

                if request_object.http_method in ['DELETE', 'POST', 'PUT']:
                    # instantiate tag resource object
                    tags = self._tc.tags()
                    self._tc.api_build_request(tags, request_object, owners)

                    del tags
                    # self.get_tags(obj)

            #
            # process associations requests
            #
            for request_object in obj.association_requests:
                # replace temporary id
                if temporary_id != new_id:
                    request_uri = str(request_object.request_uri).replace(temporary_id, new_id)
                    request_object.set_request_uri(request_uri)

                if request_object.http_method in ['DELETE', 'POST', 'PUT']:
                    # instantiate association resource object
                    # TODO: using tags here because there is no dummy object use resource directly ???
                    associations = self._tc.tags()
                    self._tc.api_build_request(associations, request_object, owners)

                    del associations
                    self.get_group_associations(obj)
                    self.get_indicator_associations(obj)

            #
            # process upload
            #
            if hasattr(obj, '_urd') and obj._urd is not None:
                request_object = obj.upload_request()
                # replace temporary id
                if temporary_id != new_id:
                    request_uri = str(request_object.request_uri).replace(temporary_id, new_id)
                    request_object.set_request_uri(request_uri)

                if request_object.http_method in ['DELETE', 'POST', 'PUT']:
                    # instantiate association resource object
                    # TODO: using tags here because there is no dummy object use resource directly ???
                    documents = self._tc.documents()
                    self._tc.api_build_request(documents, request_object, owners)

                    del documents

            #
            # process document download
            #
            if hasattr(obj, '_drd') and obj._drd is not None:
                request_object = obj.download_request()
                # replace temporary id
                if temporary_id != new_id:
                    request_uri = str(request_object.request_uri).replace(temporary_id, new_id)
                    request_object.set_request_uri(request_uri)

                # instantiate association resource object
                documents = self._tc.documents()
                document_content = self._tc.api_build_request(documents, request_object, owners)
                obj.set_document(document_content)

                del documents

        # clear filters
        del self._filter_objects[:]

    def delete(self, resource_id):
        """ """
        # switch any multiple resource request to single result request
        if self._resource_type.value % 10:
            self._resource_type = ResourceType(self._resource_type.value - 5)
        # set properties
        properties = ResourceProperties[self._resource_type.name].value(
            base_uri=self._tc.base_uri, http_method=PropertiesAction.DELETE)

        resource_object = properties.resource_object
        # set resource id
        resource_object.set_id(resource_id)
        # set resource api action
        resource_object.set_phase('delete')

        # add to temporary object storage
        roi = self.add_master_resource_obj(resource_object, resource_id)
        res = self.get_resource_by_identity(roi)

        # add resource object to parent object
        self.add_obj(res)

    def get_api_response(self):
        """ """
        return self._api_response

    def get_current_filter(self):
        """ """
        return self._current_filter

    def get_tags(self, resource_obj):
        """ """
        resource_obj.clear_tag_objects()

        resource_type = resource_obj.request_object.resource_type

        # special case for indicators
        if 500 <= resource_type.value <= 599:
            resource_type = get_resource_type(resource_obj.get_indicator())

        # switch any multiple resource request to single result request
        if resource_type.value % 10:
            resource_type = ResourceType(resource_type.value - 5)
        # get properties for the object
        properties = ResourceProperties[resource_type.name].value()

        # build request object
        if isinstance(properties, IndicatorProperties):
            request_object = RequestObject(resource_type.name, resource_obj.get_indicator())
            request_object.set_http_method(properties.http_method)
            request_object.set_request_uri(properties.tag_path.format(resource_obj.get_indicator()))
            request_object.set_owner_allowed(True)
            request_object.set_resource_pagination(True)
            request_object.set_resource_type(ResourceType.TAGS)
        elif isinstance(properties, GroupProperties):
            request_object = RequestObject(resource_type.name, resource_obj.get_id())
            request_object.set_http_method(properties.http_method)
            request_object.set_request_uri(properties.tag_path.format(resource_obj.get_id()))
            request_object.set_owner_allowed(False)
            request_object.set_resource_pagination(True)
            request_object.set_resource_type(ResourceType.TAGS)
        else:
            request_object = None

        tags = self._tc.tags()
        data_set = self._tc.api_build_request(tags, request_object, [resource_obj.get_owner_name()])
        # data_set = self._tc.api_build_request(tags, request_object)

        for obj in data_set:
            resource_obj.add_tag_object(obj)

        del tags

    #
    # Post Filter Methods
    #

    def filter_attribute(self, data, operator):
        """Post Filter"""
        if operator == FilterOperator.EQ:
            if data in self._attribute_idx:
                for data_obj in self._attribute_idx[data]:
                    data_obj.add_matched_filter(
                        'attribute|{0} ({1})'.format(data, operator.name.lower()))
                    yield data_obj
        else:
            for key, data_obj_list in self._attribute_idx.viewitems():
                if operator.value(key, data):
                    for data_obj in data_obj_list:
                        data_obj.add_matched_filter(
                            'attribute|{0} ({1})'.format(data, operator.name.lower()))
                        yield data_obj

    def filter_confidence(self, data, operator):
        """Post Filter"""
        if operator == FilterOperator.EQ:
            if data in self._confidence_idx:
                for data_obj in self._confidence_idx[data]:
                    data_obj.add_matched_filter(
                        'confidence|{0} ({1})'.format(data, operator.name.lower()))
                    yield data_obj
        else:
            for key, data_obj_list in self._confidence_idx.viewitems():
                if operator.value(int(key), data):
                    for data_obj in data_obj_list:
                        data_obj.add_matched_filter(
                            'confidence|{0} ({1})'.format(data, operator.name.lower()))
                        yield data_obj

    def filter_date_added(self, data, operator):
        """Post Filter"""
        if operator == FilterOperator.EQ:
            if data in self._date_added_idx:
                for data_obj in self._date_added_idx[data]:
                    data_obj.add_matched_filter(
                        'date_added|{0} ({1})'.format(data, operator.name.lower()))
                    yield data_obj
        else:
            for key, data_obj_list in self._date_added_idx.viewitems():
                if operator.value(key, data):
                    for data_obj in data_obj_list:
                        data_obj.add_matched_filter(
                            'date_added|{0} ({1})'.format(data, operator.name.lower()))
                        yield data_obj

    def filter_file_type(self, data, operator):
        """Post Filter"""
        if operator == FilterOperator.EQ:
            if data in self._file_type_idx:
                for data_obj in self._file_type_idx[data]:
                    data_obj.add_matched_filter(
                        'file_type|{0} ({1})'.format(data, operator.name.lower()))
                    yield data_obj
        else:
            for key, data_obj_list in self._file_type_idx.viewitems():
                if operator.value(key, data):
                    for data_obj in data_obj_list:
                        data_obj.add_matched_filter(
                            'file_type|{0} ({1})'.format(data, operator.name.lower()))
                        yield data_obj

    def filter_last_modified(self, data, operator):
        """Post Filter"""
        if operator == FilterOperator.EQ:
            if data in self._last_modified_idx:
                for data_obj in self._last_modified_idx[data]:
                    data_obj.add_matched_filter(
                        'last_modified|{0} ({1})'.format(data, operator.name.lower()))
                    yield data_obj
        else:
            for key, data_obj_list in self._last_modified_idx.viewitems():
                if operator.value(key, data):
                    for data_obj in data_obj_list:
                        data_obj.add_matched_filter(
                            'last_modified|{0} ({1})'.format(data, operator.name.lower()))
                        yield data_obj

    def filter_name(self, data, operator):
        """Post Filter"""
        if operator == FilterOperator.EQ:
            if data in self._name_idx:
                for data_obj in self._name_idx[data]:
                    data_obj.add_matched_filter(
                        'name|{0} ({1})'.format(data, operator.name.lower()))
                    yield data_obj
        """ NO OTHER STRING COMPARISON SUPPORTED AT THIS TIME """
        # else:
        #     for key, data_obj_list in self._rating_idx.viewitems():
        #         if operator.value(float(key), float(data)):
        #             for data_obj in data_obj_list:
        #                 data_obj.add_matched_filter(
        #                     'rating|{0} ({1})'.format(data, operator.name.lower()))
        #                 yield data_obj

    def filter_rating(self, data, operator):
        """Post Filter"""
        if operator == FilterOperator.EQ:
            if data in self._rating_idx:
                for data_obj in self._rating_idx[data]:
                    data_obj.add_matched_filter(
                        'rating|{0} ({1})'.format(data, operator.name.lower()))
                    yield data_obj
        else:
            for key, data_obj_list in self._rating_idx.viewitems():
                if operator.value(float(key), float(data)):
                    for data_obj in data_obj_list:
                        data_obj.add_matched_filter(
                            'rating|{0} ({1})'.format(data, operator.name.lower()))
                        yield data_obj

    def filter_threat_assess_confidence(self, data, operator):
        """Post Filter"""
        if operator == FilterOperator.EQ:
            if data in self._threat_assess_confidence_idx:
                for data_obj in self._threat_assess_confidence_idx[data]:
                    data_obj.add_matched_filter(
                        'threat assess confidence|{0} ({1})'.format(data, operator.name.lower()))
                    yield data_obj
        else:
            for key, data_obj_list in self._threat_assess_confidence_idx.viewitems():
                if operator.value(float(key), float(data)):
                    for data_obj in data_obj_list:
                        data_obj.add_matched_filter(
                            'threat assess confidence|{0} ({1})'.format(data, operator.name.lower()))
                        yield data_obj

    def filter_threat_assess_rating(self, data, operator):
        """Post Filter"""
        if operator == FilterOperator.EQ:
            if data in self._threat_assess_rating_idx:
                for data_obj in self._threat_assess_rating_idx[data]:
                    data_obj.add_matched_filter(
                        'threat assess rating|{0} ({1})'.format(data, operator.name.lower()))
                    yield data_obj
        else:
            for key, data_obj_list in self._threat_assess_rating_idx.viewitems():
                if operator.value(float(key), float(data)):
                    for data_obj in data_obj_list:
                        data_obj.add_matched_filter(
                            'threat assess rating|{0} ({1})'.format(data, operator.name.lower()))
                        yield data_obj

    def filter_tag(self, data, operator):
        """Post Filter"""
        if operator == FilterOperator.EQ:
            if data in self._tag_idx:
                for data_obj in self._tag_idx[data]:
                    data_obj.add_matched_filter(
                        'tag|{0} ({1})'.format(data, operator.name.lower()))
                    yield data_obj
        else:
            for key, data_obj_list in self._tag_idx.viewitems():
                if operator.value(key, data):
                    for data_obj in data_obj_list:
                        data_obj.add_matched_filter(
                            'tag|{0} ({1})'.format(data, operator.name.lower()))
                        yield data_obj

    def filter_type(self, data, operator):
        """Post Filter"""
        if operator == FilterOperator.EQ:
            if data in self._type_idx:
                for data_obj in self._type_idx[data]:
                    data_obj.add_matched_filter(
                        'type|{0} ({1})'.format(data, operator.name.lower()))
                    yield data_obj
        else:
            for key, data_obj_list in self._type_idx.viewitems():
                if operator.value(key, data):
                    for data_obj in data_obj_list:
                        data_obj.add_matched_filter(
                            'type|{0} ({1})'.format(data, operator.name.lower()))
                        yield data_obj

    def get_http_method(self):
        """ """
        return self._http_method

    def get_json(self):
        """ """
        return self._resource_object.get_json()

    def get_max_results(self):
        """ """
        return self._max_results

    def get_object_class(self):
        """ """
        return self._object_class

    def get_owner_allowed(self):
        """ """
        return self._owner_allowed

    def get_owners(self):
        """ """
        return self._owners

    def get_resource_pagination(self):
        """ """
        return self._resource_pagination

    def get_resource_by_id(self, data):
        """ """
        if data in self._master_res_id_idx:
            return self._master_res_id_idx[data]
        else:
            self.tcl.warning(ErrorCodes.e10012.value.format(data))
            return []

    def get_resource_by_name(self, data):
        """ """
        if data in self._master_res_id_idx:
            return self._master_res_id_idx[data]
        else:
            self.tcl.warning(ErrorCodes.e10013.value.format(data))
            return []

    def get_request_uri(self):
        """ """
        return self._request_uri

    def get_result_count(self):
        """ """
        return self._result_count

    def get_status(self):
        """ """
        return self._status

    def get_status_code(self):
        """ """
        return self._status_code

    def get_uris(self):
        """ """
        return self._uris

    @property
    def request_object(self):
        """ """
        return self._request_object

    @property
    def resource_type(self):
        """ """
        return self._resource_type

    def retrieve(self):
        """ """
        good_filters = []
        for filter_obj in self._filter_objects:
            if filter_obj.error:
                self._error = True
                for filter_error in filter_obj.get_errors():
                    self.add_error_message(filter_error)
            else:
                good_filters.append(filter_obj)

        # retrieve resources for good filters
        if not self._error_messages:
            self._tc.get_filtered_resource(self, good_filters)

        # clear filters
        del self._filter_objects[:]

        # if class is called directly
        return self

    def set_current_filter(self, data):
        """ """
        self._current_filter = data

    def set_http_method(self, data):
        """ """
        self._http_method = data

    def set_max_results(self, data_int):
        """ """
        self._max_results = int(data_int)

    def set_owner_allowed(self, data):
        """ """
        self._owner_allowed = data

    def set_resource_pagination(self, data):
        """ """
        self._resource_pagination = data

    def set_request_uri(self, data):
        """ """
        self._request_uri = data

    def set_resource_type(self, data_enum):
        """ """
        self._resource_type = data_enum

    def update(self, resource_id):
        """ """
        # switch any multiple resource request to single result request
        if self._resource_type.value % 10:
            self._resource_type = ResourceType(self._resource_type.value - 5)
        # set properties
        properties = ResourceProperties[self._resource_type.name].value(
            base_uri=self._tc.base_uri, http_method=PropertiesAction.PUT)

        # resource object
        resource_object = properties.resource_object
        # set resource id
        resource_object.set_id(resource_id)
        # set resource api action
        resource_object.set_phase('update')

        # add to temporary object storage
        self.add_master_resource_obj(resource_object, resource_id)

        res = self.get_resource_by_id(resource_id)

        # add resource object to parent object
        self.add_obj(res)

        return res

    def __iter__(self):
        """ """
        for obj in self._objects:
            yield obj

    def __len__(self):
        """ """
        return len(self._objects)

    def __str__(self):
        """ """
        obj_str = format_header('Resource Object')
        printable_items = dict(self.__dict__)
        for key, val in sorted(printable_items.viewitems()):
            obj_str += format_item(key, val)

        return obj_str
