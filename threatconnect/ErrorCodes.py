from enum import Enum


class ErrorCodes(Enum):
    """ """
    #
    # NOTE: Testing to see if Enums as error codes is usable.
    #

    e0100 = 'Settings Error: ({0}) is an invalid value. Max result counts must be a integer.'
    e0101 = 'Settings Error: ({0}) is an invalid value. Retries must be a integer.'
    e0102 = 'Settings Error: ({0}) is an invalid value. Sleep must be a integer.'
    #
    # Resource Error Codes
    #
    e0500 = 'Resource Error: ({0}) is an invalid resource type. Resource types must be a ResourceKey enum.'
    #
    # Filter Error Codes
    #
    e1000 = 'Filter Error: ({0}) is an invalid filter operator. Filter Operators must be a FilterSetOperator Enum.'
    # group filters
    e4000 = 'Filter Error: ({0}) is an invalid adversary ID. The adversary ID must be an integer.'
    e4005 = 'Filter Error: Adversary filters cannot be used with AdversaryFilterObject.'
    e4010 = 'Filter Error: ({0}) is an invalid email ID. The email ID must be an integer.'
    e4015 = 'Filter Error: Email filters cannot be used with EmailFilterObject.'
    e4020 = 'Filter Error: ({0}) is an invalid ID. The ID must be an integer.'
    e4030 = 'Filter Error: ({0}) is an invalid incident ID. The incident ID must be an integer.'
    e4035 = 'Filter Error: Incident filters cannot be used with IncidentFilterObject.'
    e4040 = 'Filter Error: ({0}) is an invalid signature ID. The signature ID must be an integer.'
    e4045 = 'Filter Error: Signature filters cannot be used with SignatureFilterObject.'
    e4050 = 'Filter Error: ({0}) is an invalid threat ID. The threat ID must be an integer.'
    e4055 = 'Filter Error: Threat filters cannot be used with ThreatFilterObject.'
    e4060 = 'Filter Error: ({0}) is an invalid victim ID. The victim ID must be an integer.'
    e4065 = 'Filter Error: Victim filters cannot be used with VictimFilterObject.'
    e4066 = 'Filter Error: Security Label filters cannot be used with VictimFilterObject.'
    e4067 = 'Filter Error: Tag filters cannot be used with VictimFilterObject.'
    e4070 = 'Filter Error: ({0}) is an invalid Security Label. The Security Label must be a string.'
    e4080 = 'Filter Error: ({0}) is an invalid Tag. The Tag must be a string.'
    e4090 = 'Filter Error: ({0}) is an invalid Hash. The Hash must be a MD5, SHA1, or SHA256.'
    # indicator filters
    e5000 = 'Filter Error: ({0}) is an invalid Group ID. The Group ID must be an integer.'
    e5001 = 'Filter Error: ({0}) is an invalid Group Type. The Group Type must be a GroupType Enum.'
    e5010 = 'Filter Error: ({0}) is an invalid indicator.'
    e5011 = 'Filter Error: ({0}) is an invalid indicator type. The Indicator Type must be an GroupType Enum.'
    e5020 = 'Filter Error: ({0}) is an invalid Victim ID. The Victim ID must be an integer.'
    e5100 = 'Filter Error: Only one type can be added to a filter. The current filter type is ({0}).'

    #
    # Resource Object Error Codes
    #
    e10000 = 'Resource Error: {0}'
    e10010 = 'Resource Error: Confidence must be >= 0 and <=100. ({0}) is not in this range.'
    e10011 = 'Resource Error: Confidence must be of integer type. ({0}) is not an integer value.'
    e10012 = 'Resource Error: ({0}) was not found in id index.'
    e10013 = 'Resource Error: ({0}) was not found in name index.'
    e10020 = 'Resource Error: ID must be of integer type. ({0}) is not an integer value.'
    e10030 = 'Resource Error: Resource Type is not configured for this object.'

    #
    # API Errors
    #
    e80000 = 'API Error: {0}'

    #
    # Runtime Errors
    #
    e90000 = 'Resource object is not properly formatted.  Missing get_id or get_name methods.'
    e90001 = 'API returned failed status code.'
