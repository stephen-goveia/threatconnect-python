""" standard """
import re

""" custom """
from threatconnect.Config.FilterOperator import FilterSetOperator
from threatconnect.DataFormatter import (format_header, format_item)
from threatconnect.ErrorCodes import ErrorCodes


class FilterObject(object):
    """ """
    def __init__(self, base_uri, tcl):
        """ """
        self.base_uri = base_uri

        # threatconnect logger
        self.tcl = tcl

        self._api_filter_names = []
        self._error = False
        self._errors = []
        self._filter_operator = FilterSetOperator.AND
        self._filter_object_type = None
        self._post_filter_names = []
        self._post_filters = []
        self._resource_type = None
        self._request_object = None
        self._request_objects = []

    @property
    def error(self):
        """ """
        return self._error

    def add_error(self, data):
        """ """
        self._errors.append(data)

    def _add_request_objects(self, data_obj):
        """ """
        self._request_objects.append(data_obj)

    def add_api_filter_name(self, data):
        """ """
        self._api_filter_names.append(data)

    def add_filter_operator(self, data_enum):
        """ """
        if not isinstance(data_enum, FilterSetOperator):
            self.add_error(ErrorCodes.e1000.value.format(data_enum))
        else:
            self._filter_operator = data_enum

    def add_post_filter(self, data_obj):
        """ """
        self._post_filters.append(data_obj)

    def add_post_filter_names(self, data):
        """ """
        self._post_filter_names.append(data)

    # def get_base_uri(self):
    #     """ """
    #     return self._base_uri

    def get_errors(self):
        """ """
        return self._errors

    def get_filter_operator(self):
        """ """
        return self._filter_operator

    def get_post_filters(self):
        """ """
        for obj in self._post_filters:
            yield obj

    def get_post_filters_len(self):
        """ """
        return len(self._post_filters)

    @property
    def api_filter_names(self):
        """ """
        return sorted(self._api_filter_names)

    @property
    def filters(self):
        """ """
        filters = []
        for filter in sorted(self._api_filter_names):
            if re.findall('^add_', filter):
                filters.append(filter)
        for filter in sorted(self._post_filter_names):
            if re.findall('^add_', filter):
                filters.append(filter)
        return filters

    @property
    def post_filter_names(self):
        """ """
        return sorted(self._post_filter_names)

    @property
    def request_object(self):
        """ """
        return self._request_object

    @property
    def resource_type(self):
        """ """
        return self._resource_type

    def __iter__(self):
        """ """
        for obj in self._request_objects:
            yield obj

    def __len__(self):
        """ """
        return len(self._request_objects)

    def __str__(self):
        """ """
        obj_str = format_header('{0} Filter Object'.format(self._resource_type.name))
        printable_items = dict(self.__dict__)
        printable_items.pop('_request_objects')
        for key, val in sorted(printable_items.viewitems()):
            obj_str += format_item(key, val)

        return obj_str

