""" standard """

""" custom """
from threatconnect.ErrorCodes import ErrorCodes


def parse_attribute(attribute_dict):
    """ """
    # store the resource object in the master resource object list
    # roi = resource_obj.add_master_resource_obj(AttributeObject(), attribute_dict['id'])

    # retrieve the resource object and update data
    # attribute = resource_obj.get_resource_by_identity(roi)
    attribute = AttributeObject()

    #
    # standard values
    #
    attribute.set_date_added(attribute_dict['dateAdded'])
    attribute.set_displayed(attribute_dict['displayed'])
    attribute.set_id(attribute_dict['id'])
    attribute.set_last_modified(attribute_dict['lastModified'])
    attribute.set_type(attribute_dict['type'])
    attribute.set_value(attribute_dict['value'])

    return attribute


class AttributeObject(object):
    __slots__ = (
        '_date_added',
        '_displayed',
        '_id',
        '_last_modified',
        '_required_attrs',
        '_type',
        '_value',
        '_validated',
        '_writable_attrs',
    )

    def __init__(self):
        self._date_added = None
        self._displayed = None
        self._id = None
        self._last_modified = None
        self._required_attrs = ['type', 'value']
        self._type = None
        self._value = None
        self._writable_attrs = {
            '_displayed': 'set_displayed',
            '_type': 'set_type',
            '_value': 'set_value'
        }

        # validation
        self._validated = False

    #
    # unicode
    #
    @staticmethod
    def _uni(data):
        """ """
        if isinstance(data, (int, list, dict)):
            return data
        elif not isinstance(data, unicode):
            return unicode(data, errors='ignore')
        else:
            return data

    """ shared attribute methods """

    #
    # date_added
    #
    @property
    def date_added(self):
        """ """
        return self._date_added

    def set_date_added(self, data):
        """Read-Only attribute metadata"""
        self._date_added = data

    #
    # displayed
    #
    @property
    def displayed(self):
        """ """
        return self._displayed

    def set_displayed(self, data):
        """Read-Write attribute metadata"""
        self._displayed = data

    #
    # id
    #
    @property
    def id(self):
        """ """
        return self._id

    def set_id(self, data):
        """Read-Only attribute metadata"""
        if isinstance(data, int):
            self._id = data
        else:
            raise AttributeError(ErrorCodes.e10020.value.format(data))

    #
    # last_modified
    #
    @property
    def last_modified(self):
        """ """
        return self._last_modified

    def set_last_modified(self, data):
        """Read-Only attribute metadata"""
        self._last_modified = data

    #
    # type
    #
    @property
    def type(self):
        """ """
        return self._type

    def set_type(self, data):
        """Read-Write attribute metadata"""
        self._type = self._uni(data)

    #
    # value
    #
    @property
    def value(self):
        """ """
        return self._value

    def set_value(self, data):
        """Read-Write attribute metadata"""
        self._value = self._uni(data)

    #
    # validated
    #
    @property
    def validated(self):
        """ """
        return self._validated

    def validate(self):
        """ """
        for required in self._required_attrs:
            if getattr(self, required) is None:
                self._validated = False
                return

        self._validated = True

    #
    # add print method
    #
    def __str__(self):
        """allow object to be displayed with print"""

        printable_string = '\n{0:_^80}\n'.format('Attribute Object Properties')

        #
        # retrievable methods
        #
        printable_string += '{0:40}\n'.format('Retrievable Methods')
        printable_string += ('  {0:<28}: {1:<50}\n'.format('id', self.id))
        printable_string += ('  {0:<28}: {1:<50}\n'.format('type', self.type))
        printable_string += ('  {0:<28}: {1:<50}\n'.format('value', self.value))
        printable_string += ('  {0:<28}: {1:<50}\n'.format('displayed', self.displayed))
        printable_string += ('  {0:<28}: {1:<50}\n'.format('date_added', self.date_added))
        printable_string += ('  {0:<28}: {1:<50}\n'.format('last_modified', self.last_modified))

        return printable_string
