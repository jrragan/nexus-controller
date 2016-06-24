import logging

__version__ = '2014.3.3.1'

"""
3/3/14 - tweaked namespace function
3/1/14 - modified parse_get_nsmap to return schema surrounded by braces
2/28/14 - added parse_get_nsmap function
2/12/14 - added parse_xml_heirarchy function
2/11/14 - added find_element function
1/27/14 - initial release
"""


import itertools
from lxml import etree
#import xml.etree.ElementTree as etree

__author__ = 'rragan'

VLANSCHEMA = "vlan_mgr_cli"
INTSCHEMA = "if_manager"
ETHPCMDC3SCHEMA = "eth_pcm_dc3"
IPSCHEMA = "ip"
HSRPSCHEMA = "hsrp_engine"
VDCSCHEMA = "vdc_mgr"
SYSMGRCLISCHEMA = "sysmgrcli"

logger = logging.getLogger('nxosXMLFunctions')

def buildshowcommand(message=None):
    """
    Function to build wrapper around show commands
    @param message - can be a list or tuple

    for example ['port-channel', 'summary']returns
    ::
    <show>
       <port-channel>
          <summary/>
       </port-channel.
    </show>

    @param message: or can be Element object to be wrapped

    @return: Element object

    """

    showelement = etree.Element("show")
    if (isinstance(message, list) or isinstance(message, tuple)) and len(message):
        topele = etree.Element(message[0])
        prevele = topele
        for s in message[1:]:
            thisele = etree.SubElement(prevele, s)
            prevele = thisele
        showelement.append(topele)
    elif isinstance(message, etree._Element):
        showelement.append(message)
    return showelement


def buildshowvlancommand(message=None, vlanid=None):
    """

    @param message: str with a modifier such as brief
    @param vlanids: str of vlan for command show vlan id
    @return: Element object

    """
    vlanelement = etree.Element("vlan")
    if message == "brief":
        vlanelement = etree.SubElement(vlanelement, "brief")
    if vlanid is not None:
        idelement = etree.SubElement(vlanelement, "id")
        vlanidelement = etree.SubElement(idelement, "vlan-id")
        vlanidelement.text = vlanid
    return buildshowcommand(message=vlanelement)

def buildshowintcommand(subcommand):
    """

    @param message: str with a modifier such as brief
    @param vlanids: str of vlan for command show vlan id
    @return: Element object

    """
    return buildshowcommand(('interface', subcommand))

def find_element(tag, schema, parsed_doc):
    """
    Takes a tag or list of tags, a schema and lxml object, returns a list of content for all instances of tag

    @param tag: str or list of str
    @param schema: str
    @param parsed_doc: object
    @return: dict of form {taq : content}
    """
    if isinstance(tag, str):
        tag = [tag]
    tags = ["{0}{1}".format(schema, t) for t in tag]
    logger.debug("tags {}".format(tags))
    content = {}
    for element in parsed_doc.iter():
        logger.debug("element {}".format(element))
        if element.tag in tags:
            logger.debug("element.tag {}".format(element.tag))
            t = tag[tags.index(element.tag)]
            logger.debug("t {}".format(t))
            content[t] = element.text
    logger.debug("find_element: return content {}".format(content))
    return content

def parse_xml_heirarchy(htag, tag, schema, parsed_doc):
    """

    @param htag: str, tag to indicate place heirarchy
    @param tag: str or list of str, tags to find within the heirarchy
    @param schema: str
    @param parsed_doc: object
    @return: list of dictionaries [{taq : content}]
    """
    content = []
    for element in parsed_doc.iter("{0}{1}".format(schema, htag)):
        v = find_element(tag, schema, element)
        logger.debug("v {}".format(v))
        if v:
            content.append(v)
        logger.debug("parse_xml_heirarchy: content {}".format(content))
    logger.debug("parse_xml_heirarchy: returned content {}".format(content))
    return content


def parse_get_nsmap(parsed_doc):
    """

    @param parsed_doc:
    """
    nsdict = parsed_doc.nsmap
    if 'mod' in nsdict:
        return "{{{}}}".format(nsdict['mod'])
    elif None in nsdict:
        return "{{{}}}".format(nsdict[None])
    else:
        return ''