import logging

__version__ = '2014.1.9.1'

from lxml import etree
#import xml.etree.ElementTree as etree
from nxos_XML_errors import NetConfRPCError, XMLError, ServerClosedChannelError, NotConnectedError

#: Base NETCONF namespace
BASE_NS_1_0 = "urn:ietf:params:xml:ns:netconf:base:1.0"
# NXOS_1_0
NXOS_1_0 = "http://www.cisco.com/nxos:1.0"
# NXOS_IF
NXOS_IF = "http://www.cisco.com/nxos:1.0:if_manager"

# NETCONF XML Elements
GETEL = ('get',)
EDITEL = ('edit-config',)
TARGETEL = ('target', 'running')
CONFIGEL = ('config',)
CLOSEEL = ('close-session',)
KILLEL = ('kill-session', 'session-id')
EXECEL = ('exec-command',)
CMDEL = ('cmd',)
CAPSEL = ('capabilities',)
CAPEL = ('capability',)

logger = logging.getLogger('xmlfunctions')

def _rpc_error_parser(root):
    """
    Parses
    @param root: lxml object
    @return: raises exception if RPC error detected
    """
    error = root.findall("{{{0}}}rpc-error".format(BASE_NS_1_0))
    if error:
        for e in error:
            for t in e.itertext():
                if t == 'current session timed out':
                    raise NotConnectedError(
                    "Server indicates that the current session has timed out: {}".format(etree.tostring(root)))
        logger.critical("RPC Error from Server: {}".format(etree.tostring(root, encoding='unicode',  pretty_print=True)))
        raise NetConfRPCError("RPC Error from Server: {0}".format(etree.tostring(root, encoding='unicode',  pretty_print=True)))


def rpcparse(rpcreply, rpcmessageid=None):
    """
    Parses the rpc reply message received from server
    Stolen from ncclient

    @type rpcreply: str
    @param rpcreply: string containing the rpc reply message
    """

    if rpcreply:
        root = etree.fromstring(rpcreply)
        if rpcmessageid:
            attribs = root.attrib
            if 'message-id' in attribs and attribs['message-id'] != rpcmessageid:
                raise NetConfRPCError("RPC Error from Server: Wrong message-id in reply {0}".format(rpcreply))
                # Per RFC 4741 an <ok/> tag is sent when there are no errors or warnings or data
        ok = root.find("{{{0}}}ok".format(BASE_NS_1_0))
        if ok is None:
            _rpc_error_parser(root)

def buildclienthello(client_capabilities=('urn:ietf:params:xml:ns:netconf:base:1.0',)):
    """
    str -> (tuple)

    takes client_capabilities as a tuple or a list, then constructs and returns a hello message
    @param client_capabilities: tuple or list of client capabilities
    @return: prettily formatted xml netconf hello message
    """

    #build namespace mapping dictionary
    NSMAP = buildnamespacedict(None)

    helloelement = buildtoplevelelement('hello', NSMAP, None)
    capabilities = buildelement(helloelement, CAPSEL, BASE_NS_1_0)
    for i in client_capabilities:
        buildelement(capabilities, CAPEL, BASE_NS_1_0).text = i
    client_hello = etree.tostring(helloelement, encoding="unicode")
    logger.debug("buildclienthello: client hello: {}".format(client_hello))
    return client_hello


def buildnxosmessage(nctype, schema, rpcmessageid, message=None, ncfilter=None):
    """
    str -> (str, str, str, str, tuple)

    -    @param nctype: string indicating type of rpc message to build for the client accepted types are close-session, get, edit-config and kill-session
    -    @param rpcmessageid: str containing message-id to use in rpc message
    -    @param message: string containing nx-os xml to be wrapped
    -    @param schema: string with name of nx-os xml
    -    @param ncfilter: can be None or a string indicating type (xpath or subtree) or a tuple of the form (type, filter)
    -    @return: xml message

    """
    #build namespace mapping dictionary
    NSMAP = buildnamespacedict(schema)

    #build top layer rpc element with namespace and message id
    rpcelement = buildtoplevelelement('rpc', NSMAP, rpcmessageid)

    #parse the nx-os xml message
    if type(message) == str and (nctype != 'kill-session'):
        parser = etree.XMLParser()
        nxosroot = etree.fromstring(message, parser=parser)
    elif type(message) == etree._Element:
        nxosroot = message

    #check to netconf type
    if nctype == 'get':
        #build get element
        getelement = buildelement(rpcelement, GETEL, BASE_NS_1_0)
        #build filter element. this should only be needed for the get operation
        if ncfilter is not None:
            filterelement = build_filter(ncfilter)
            #add nx-os specific message to filter element
            if message is not None:
                filterelement.append(nxosroot)
            getelement.append(filterelement)
        elif message:
            getelement.append(nxosroot)
        else:
            raise XMLError("Cannot build get message with supplied parameters")
    elif nctype == 'edit-config':
        if message is None:
            raise XMLError("Message cannot be Nonetype when nctype is edit-config")
        editelement = buildelement(rpcelement, EDITEL, BASE_NS_1_0)
        targetelement = buildelement(editelement, TARGETEL, BASE_NS_1_0)
        configelement = buildelement(editelement, CONFIGEL, BASE_NS_1_0)
        configelement.append(nxosroot)
    elif nctype == 'close-session':
        #closeelement = etree.SubElement(rpcelement, '{{{0}}}close-session'.format(BASE_NS_1_0))
        closeelement = buildelement(rpcelement, CLOSEEL, BASE_NS_1_0)
    elif nctype == 'kill-session':
        sessionelement = buildelement(rpcelement, KILLEL, BASE_NS_1_0)
        sessionelement.text = message
    else:
        raise XMLError("nctype " + nctype + " is unsupported in NX-OS")
    clientrpcelement = etree.tostring(rpcelement, encoding="unicode" )
    return clientrpcelement


def buildelement(topelement, elementstuple, schemaname):
    """


    @rtype : etree.Element
    @param topelement: etree.Element object
    @param elementstuple: tuple or list of subelements

    return and etree.Element object
    """

    newelement = etree.SubElement(topelement, '{{{0}}}{1}'.format(schemaname, elementstuple[0]))
    if len(elementstuple) > 1:
        return buildelement(newelement, elementstuple[1:], schemaname)
    elif len(elementstuple) == 1:
        return newelement
    else:
        raise XMLError("buildelement cannot be called with an empty sequence")


def build_filter(spec, capcheck=None):
    """
    stolen from ncclient

    @param spec: str or Tuple representing the filter
    @param capcheck:
    @return: Element object representing the netconf filter
    """
    if isinstance(spec, tuple):
        filtype, criteria = spec
        rep = etree.Element('{{{0}}}filter'.format(BASE_NS_1_0), type=filtype)
        if filtype == "xpath":
            rep.attrib["select"] = criteria
        elif filtype == "subtree":
            parser = etree.XMLParser()
            nxosroot = etree.fromstring(criteria, parser=parser)
            rep.append(nxosroot)
        else:
            raise XMLError("Invalid filter type")
    else:
        rep = etree.Element('{{{0}}}filter'.format(BASE_NS_1_0), type=spec)
    return rep


def buildnamespacedict(schema):
    """

    dict <- (str)

    takes the NX-OS schema as a string
    returns a schema namespace mapping dictionary

    @rtype : dict
    @param schema: str containing None or the name of the NX-OS schema
    @return: dictionary of namespace mapping
    """
    #build namespace mapping dictionary

    NSMAP = {"nc": BASE_NS_1_0}
    if schema is None:
        return NSMAP
    elif schema:
        NSMAP[None] = NXOS_1_0 + ":" + schema
    else:
        NSMAP['nxos'] = NXOS_1_0
    return NSMAP


def buildnxosclimessage(clilist, rpcmessageid):
    """
    str <- list, str

    Takes a list of nx-os commands and returns the corresponding xml message

    """

    NSMAP = buildnamespacedict('')
    rpcelement = buildtoplevelelement('rpc', NSMAP, rpcmessageid)
    execcommand = buildelement(rpcelement, EXECEL, NXOS_1_0)
    for i in clilist:
        buildelement(execcommand, CMDEL, NXOS_1_0).text = i
    cli_message = etree.tostring(rpcelement, encoding="unicode")
    return cli_message


def buildtoplevelelement(elementname, nsmapdict, rpcmessageid=None):
    xmlelement = etree.Element('{{{0}}}{1}'.format(BASE_NS_1_0, elementname), nsmap=nsmapdict)
    if rpcmessageid:
        xmlelementattribs = xmlelement.attrib
        xmlelementattribs["message-id"] = rpcmessageid

    return xmlelement


def strip_ns_prefix(tree):
    # xpath query for selecting all element nodes in namespace
    query = "descendant-or-self::*[namespace-uri()!='']"
    # for each element returned by the above xpath query...
    for element in tree.xpath(query):
        # replace element name with it's local name
        element.tag = etree.QName(element).localname
    return tree