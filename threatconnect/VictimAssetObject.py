""" standard """
import json

""" custom """
from threatconnect.Config.ResourceType import ResourceType
# from threatconnect.ErrorCodes import ErrorCodes


def parse_victim_asset(victim_asset_dict):
    """ """
    victim_asset = VictimAssetObject()
    victim_asset.set_id(victim_asset_dict['id'])
    victim_asset.set_name(victim_asset_dict['name'])
    victim_asset.set_type(victim_asset_dict['type'])
    victim_asset.set_weblink(victim_asset_dict['webLink'])

    #
    # emailAddress specific
    #
    if 'address' in victim_asset_dict:
        victim_asset.set_address(victim_asset_dict['address'])
    if 'addressType' in victim_asset_dict:
        victim_asset.set_address_type(victim_asset_dict['addressType'])

    #
    # networkAccount specific
    #
    if 'account' in victim_asset_dict:
        victim_asset.set_account(victim_asset_dict['account'])
    if 'network' in victim_asset_dict:
        victim_asset.set_network(victim_asset_dict['network'])

    #
    # phoneType specific
    #
    if 'phoneType' in victim_asset_dict:
        victim_asset.set_phone_type(victim_asset_dict['phoneType'])

    #
    # socialNetwork specific
    #
    # account - already set on network specific
    # network - already set on network specific

    #
    # WebSite specific
    #
    if 'webSite' in victim_asset_dict:
        victim_asset.set_website(victim_asset_dict['webSite'])

    return victim_asset


class VictimAssetObject(object):
    __slots__ = (
        '_account',  # networkAccount/socialNetwork specific
        '_address',  # emailAddress specific
        '_address_type',  # emailAddress specific
        '_id',
        '_name',
        '_network',  # networkAccount/socialNetwork specific
        '_phone_type',  # phoneType specific
        '_properties',
        '_resource_type',
        '_type',
        '_uri_attribute',
        '_weblink',
        '_website',  # webSite specific
    )

    def __init__(self, resource_type=None):
        self._account = None
        self._address = None
        self._address_type = None
        self._id = None
        self._name = None
        self._network = None
        self._phone_type = None
        self._properties = {
            '_name': {
                'api_field': 'name',
                'method': 'set_name',
                'required': True,
            },
        }
        self._resource_type = None
        self._type = None
        self._uri_attribute = None
        self._weblink = None
        self._website = None

        if resource_type is not None:
            self.set_type(resource_type)

    #
    # unicode
    #
    @staticmethod
    def _uni(data):
        """ """
        if data is None or isinstance(data, (int, list, dict)):
            return data
        elif not isinstance(data, unicode):
            return unicode(data, errors='ignore')
        else:
            return data

    """ victim asset methods """

    #
    # account (networkAccount/socialNetwork specific)
    #
    @property
    def account(self):
        """ """
        if self._resource_type in [ResourceType.VICTIM_NETWORK_ACCOUNTS, ResourceType.VICTIM_SOCIAL_NETWORKS]:
            return self._account
        else:
            raise AttributeError('Account is not support by this Resource Type.')

    def set_account(self, data):
        """Read-Write victim asset metadata"""
        if self._resource_type in [ResourceType.VICTIM_NETWORK_ACCOUNTS, ResourceType.VICTIM_SOCIAL_NETWORKS]:
            self._account = data
        else:
            raise AttributeError('Account is not support by this Resource Type.')

    #
    # address (emailAddress specific)
    #
    @property
    def address(self):
        """ """
        if self._resource_type == ResourceType.VICTIM_EMAIL_ADDRESSES:
            return self._address
        else:
            raise AttributeError('Address is not support by this Resource Type.')

    def set_address(self, data):
        """Read-Write victim asset metadata"""
        if self._resource_type == ResourceType.VICTIM_EMAIL_ADDRESSES:
            self._address = data
        else:
            raise AttributeError('Address is not support by this Resource Type.')

    #
    # address_type (emailAddress specific)
    #
    @property
    def address_type(self):
        """ """
        if self._resource_type == ResourceType.VICTIM_EMAIL_ADDRESSES:
            return self._address_type
        else:
            raise AttributeError('Address Type is not support by this Resource Type.')

    def set_address_type(self, data):
        """Read-Only victim asset metadata"""
        if self._resource_type == ResourceType.VICTIM_EMAIL_ADDRESSES:
            self._address_type = data
        else:
            raise AttributeError('Address is not support by this Resource Type.')

    @property
    def gen_body(self):
        """ generate json body for POST and PUT API requests """
        body_dict = {}
        for prop, values in self._properties.items():
            if getattr(self, prop) is not None:
                body_dict[values['api_field']] = getattr(self, prop)
        return json.dumps(body_dict)

    #
    # id
    #
    @property
    def id(self):
        """ """
        return self._id

    def set_id(self, data):
        """Read-Only victim asset metadata"""
        self._id = data

    #
    # name
    #
    @property
    def name(self):
        """ """
        return self._name

    def set_name(self, data):
        """Read-Write victim asset metadata"""
        self._name = data

    #
    # network (networkAccount/socialNetwork specific)
    #
    @property
    def network(self):
        """ """
        if self._resource_type in [ResourceType.VICTIM_NETWORK_ACCOUNTS, ResourceType.VICTIM_SOCIAL_NETWORKS]:
            return self._network
        else:
            raise AttributeError('Network is not support by this Resource Type.')

    def set_network(self, data):
        """Read-Write victim asset metadata"""
        if self._resource_type in [ResourceType.VICTIM_NETWORK_ACCOUNTS, ResourceType.VICTIM_SOCIAL_NETWORKS]:
            self._network = data
        else:
            raise AttributeError('Network is not support by this Resource Type.')

    #
    # phone_type (phoneType specific)
    #
    @property
    def phone_type(self):
        """ """
        if self._resource_type == ResourceType.VICTIM_PHONES:
            return self._phone_type
        else:
            raise AttributeError('Phone Type is not support by this Resource Type.')

    def set_phone_type(self, data):
        """Read-Only victim asset metadata"""
        if self._resource_type == ResourceType.VICTIM_PHONES:
            self._phone_type = data
        else:
            raise AttributeError('Phone Type is not support by this Resource Type.')

    #
    # resource type
    #
    @property
    def resource_type(self):
        """ """
        return self._resource_type

    #
    # type
    #
    @property
    def type(self):
        """ """
        return self._type

    def set_type(self, data):
        """Read-Only victim asset metadata"""
        if data == 'EmailAddress' or data == ResourceType.VICTIM_EMAIL_ADDRESSES:
            self._resource_type = ResourceType.VICTIM_EMAIL_ADDRESSES
            self._type = data
            self._uri_attribute = 'emailAddresses'

            self._properties['_address'] = {
                'api_field': 'address',
                'method': 'set_address',
                'required': True,
            }
            self._properties['_address_type'] = {
                'api_field': 'addressType',
                'method': 'set_address_type',
                'required': True,
            }
        elif data == 'NetworkAccount' or data == ResourceType.VICTIM_NETWORK_ACCOUNTS:
            self._resource_type = ResourceType.VICTIM_NETWORK_ACCOUNTS
            self._type = data
            self._uri_attribute = 'networkAccounts'

            self._properties['_account'] = {
                'api_field': 'account',
                'method': 'set_account',
                'required': True,
            }
            self._properties['_network'] = {
                'api_field': 'network',
                'method': 'set_network',
                'required': True,
            }
        elif data == 'Phone' or data == ResourceType.VICTIM_PHONES:
            self._resource_type = ResourceType.VICTIM_PHONES
            self._type = data
            self._uri_attribute = 'phoneNumbers'

            self._properties['_phone_type'] = {
                'api_field': 'phoneType',
                'method': 'set_phone_type',
                'required': True,
            }
        elif data == 'SocialNetwork' or data == ResourceType.VICTIM_SOCIAL_NETWORKS:
            self._resource_type = ResourceType.VICTIM_SOCIAL_NETWORKS
            self._type = data
            self._uri_attribute = 'socialNetworks'

            self._properties['_account'] = {
                'api_field': 'account',
                'method': 'set_account',
                'required': True,
            }
            self._properties['_network'] = {
                'api_field': 'network',
                'method': 'set_network',
                'required': True,
            }
        elif data == 'WebSite' or data == ResourceType.VICTIM_WEBSITES:
            self._resource_type = ResourceType.VICTIM_WEBSITES
            self._type = data
            self._uri_attribute = 'webSites'

            self._properties['_website'] = {
                'api_field': 'webSite',
                'method': 'set_website',
                'required': True,
            }
        else:
            raise AttributeError('Invalid Victim Asset Type ({0})'.format(data))

    #
    # uri attribute
    #
    @property
    def uri_attribute(self):
        """ """
        return self._uri_attribute

    #
    # weblink
    #
    @property
    def weblink(self):
        """ """
        return self._weblink

    def set_weblink(self, data):
        """Read-Only victim asset metadata"""
        self._weblink = data

    #
    # website (webSite specific)
    #
    @property
    def website(self):
        """ """
        if self._resource_type == ResourceType.VICTIM_WEBSITES:
            return self._website
        else:
            raise AttributeError('Phone Type is not support by this Resource Type.')

    def set_website(self, data):
        """Read-Only victim asset metadata"""
        if self._resource_type == ResourceType.VICTIM_WEBSITES:
            self._website = data
        else:
            raise AttributeError('Phone Type is not support by this Resource Type.')

    #
    # add print method
    #
    def __str__(self):
        """allow object to be displayed with print"""

        printable_string = '\n{0:_^80}\n'.format('Victim Asset Object Properties')

        #
        # retrievable methods
        #
        printable_string += '{0:40}\n'.format('Retrievable Methods')
        printable_string += ('  {0:<28}: {1:<50}\n'.format('id', self.id))
        printable_string += ('  {0:<28}: {1:<50}\n'.format('name', self.name))
        for prop in sorted(self._properties.keys()):
            value = getattr(self, prop)
            printable_string += ('  {0:<28}: {1:<50}\n'.format(prop, value))


        printable_string += ('  {0:<28}: {1:<50}\n'.format('type', self.type))
        printable_string += ('  {0:<28}: {1:<50}\n'.format('weblink', self.weblink))

        #
        # writable properties
        #
        printable_string += '\n{0:40}\n'.format('Writable Properties')
        for prop, values in sorted(self._properties.items()):
            printable_string += ('  {0:<28}: {1:<50}\n'.format(
                values['api_field'], '{0} (Required: {1})'.format(values['method'], str(values['required']))))

        return printable_string
