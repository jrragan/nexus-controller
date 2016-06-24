__version__ = '2013.12.27.1'

class NxosXMLError(Exception):
    """Base type for all nx-os XML errors"""
    pass


class OperationError(NxosXMLError):
    pass


class TimeoutExpiredError(NxosXMLError):
    pass

class ServerClosedChannelError(NxosXMLError):
    pass

class MissingCapabilityError(NxosXMLError):
    pass


class XMLError(NxosXMLError):
    pass

class NetConfRPCError(NxosXMLError):
    pass

class NotConnectedError(NxosXMLError):
    pass

class HostNotFoundError(NxosXMLError):
    pass