""" standard """
from pprint import pformat

""" custom """
from threatconnect.DataFormatter import format_header, format_item


class ReportEntry(object):
    """ """

    def __init__(self):
        """ """
        self._action = None
        self._data = []
        self._request_urls = []
        self._resource_type = None
        self._status = None
        self._status_code = None

    def add_data(self, data):
        """ """
        self._data.append(data)

    def add_request_url(self, data):
        """ """
        self._request_urls.append(data.encode('utf-8', 'ignore'))

    def set_action(self, data):
        """ """
        # self._action = data.encode('utf-8', 'ignore')
        # self._action = data.decode('ascii', 'ignore')
        self._action = unicode(data, errors='ignore')

    def set_resource_type(self, data_enum):
        """ """
        self._resource_type = data_enum

    def set_status(self, data):
        """ """
        self._status = data.encode('utf-8', 'ignore')

    def set_status_code(self, data_int):
        """ """
        self._status_code = data_int

    @property
    def action(self):
        """ """
        return self._action

    @property
    def data(self):
        """ """
        return self._data

    @property
    def request_urls(self):
        """ """
        return self._request_urls

    @property
    def resource_type(self):
        """ """
        return self._resource_type

    @property
    def status(self):
        """ """
        return self._status

    @property
    def status_code(self):
        """ """
        return self._status_code

    def __str__(self):
        """ """
        obj_str = format_header('{0}'.format(self.action), '.', '.')
        obj_str += format_item('Status', self._status)
        obj_str += format_item('Status Code', self._status_code)
        obj_str += format_item('Request URLs', self.request_urls)
        obj_str += format_item('Data', '')
        for data in self._data:
            for k, v in data.viewitems():
                obj_str += format_item('{0}'.format(k), v, 1)

        return obj_str.encode('utf-8')

