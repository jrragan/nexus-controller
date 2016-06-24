from pprint import pprint

import nxos_XML_errors

__version__ = '2016.6.12.1'

#todo add __repr__ and __str__ methods
#todo create xml objects that can be reused

import functools

import random
import socket
import sys
import traceback

from lxml import etree
#import xml.etree.ElementTree as etree

from ncssh import SshConnect


import logging

from nxos_XML_errors import TimeoutExpiredError, XMLError, NetConfRPCError

# Static Variables, global for now
from xmlFunctions import buildclienthello, rpcparse, buildnxosmessage, buildnxosclimessage, buildtoplevelelement, \
    strip_ns_prefix

"""
3/18/2014 - reraised xml server error in _send
"""

MSG_DELIM = "]]>]]>"
DEBUG = False
KEYFILE = "paramikolocalhostkeys"

logger = logging.getLogger('netconf')

logger.info("Starting netconf session")




def netconfbuilder(func):
    @functools.wraps(func)
    def decorator(self, *args, **kwargs):
        if self.ncconnected:
            self.logger.debug('netconfbuilder: instance %s of class %s is now decorated with netconfbuilder, whee!' % (self, self.__class__))
            self.logger.debug("netconfbuilder: Building rpc to send to ".format(self.host))
            self.logger.debug("netconfbuilder: method {}".format(func))
            self.logger.debug("netconfbuilder: args {}".format(str(args)))
            self.logger.debug("netconfbuilder: kwargs {}".format(str(kwargs)))
            rpcmessageid = str(self.rpcmessageid)
            try:
                nxosmessage = func(self, *args, **kwargs)
            except:
                exc_type, exc_value, exc_traceback = sys.exc_info()
                stacktrace = traceback.extract_tb(exc_traceback)
                self.logger.critical("netconfbuilder: Error building the rpc command ")
                self.logger.debug(sys.exc_info())
                self.logger.debug(stacktrace)
                raise

            self.rpcmessageid = None

            logger.debug("netconfbuilder: Constructed nxos message: ".format(str(nxosmessage)))
            logger.debug("netconfbuilder: Sending message to server")
            try:
                return self._send(nxosmessage, rpcmessageid=rpcmessageid)
            except:
                exc_type, exc_value, exc_traceback = sys.exc_info()
                stacktrace = traceback.extract_tb(exc_traceback)
                logger.critical("netconfbuilder: Error sending xml message")
                logger.debug(sys.exc_info())
                logger.debug(stacktrace)
                raise
        else:
            self.logger.error("netconfbuilder: The ssh connection to {} is currently closed. Please reconnect and try again.".format(self.host))
            raise nxos_XML_errors.NotConnectedError(
                "The ssh connection to {} is currently closed. Please reconnect and try again.".format(self.host))
    return decorator


class NxosConnect(SshConnect):
    """
    Sets up a netconf over ssh session

    """

    def __init__(self, host):

        """
        Initializes NX-OS XML object
        @param host: string containing name or IP address of the nx-os host
        """
        self.logger = logging.getLogger('netconf.NxosConnect')
        self.logger.debug("Calling SSH object initiator for " + host)
        SshConnect.__init__(self, host)

        self.server_capabilities = None
        self.sessionid = None
        self._ncconnected = False
        self._rpcmessageid = None
        self._useprovidedmessageid = False

    def nc_sshconnect(self, *args, **kwargs):
        """
        Connect via SSH and initialize the NETCONF session. First attempts the publickey authentication method and then password authentication.

            To disable attempting publickey authentication altogether,
            call with *allow_agent* and *look_for_keys* as `False`.

            Options

            -    *host* is the hostname or IP address to connect to

            -    *port* is by default 22, but some netconf devices use 830

            -    *timeout* is an optional timeout for socket connect

            -    *unknown_host_cb* is the method for handling unknown hosts. Only 'autoaddpolicy' is supported

            -    *username* is the username to use for SSH authentication

            -    *password* is the password used if using password authentication, or the passphrase to use for unlocking keys that require it

            -    *host_key_filename* is a filename where the host keys are located. If *filename* is not specified, looks in the default locations i.e. :file:`~/.ssh/known_hosts` and :file:`~/ssh/known_hosts` for Windows

            -    *key_filename* is a filename where a the private key to be used can be found

            -    *allow_agent* enables querying SSH agent (if found) for keys

            -    *look_for_keys* enables looking in the usual locations for ssh keys (e.g. :file:`~/.ssh/id_*`)

            -    *command_timeout* is the maximum time (float) to wait for a response from the server, 30 second default

                """

        self.sshconnect(host=self.host, *args, **kwargs)

        self.logger.debug("Waiting for hello from host " + self.host)
        self._ncconnected = self.sshconnected
        self._netconf_hello()
        self._generaterpcmessageid()

    #SSH object requires that the subclass define the object
    def setup_channel(self):
        """
        I need a channel so I can activate the nx-os xml subsystem
        """
        self.ssh_subsystem('xmlagent')

    #Now I expect to see a hello from the server
    def _netconf_hello(self):
        """
        Looking for hello from server
        Replies with client hello
        
        @type self: NxosConnect

        Once a connection is opened to the nx-os xmlagent subsystem, thye server should immediately return a
        hello message. This method waits for the hello and parses it for errors.

        If we did not receive a hello, raise XMLError
        If a hello was received, parse and log the capabilities
        If no capabilities in the message, raise XMLError
        Check the message for a session id, if not present raise XMLError

        Construct the client hello, by calling the xmlFunctions.buildclienthello function
        Send client hello to server
        nx-os does not reply to the client hello unless there is an error. This is annoying but compliant
        with the RFC. To account for this, the command_timeout used by ncssh.rpexpect is reset to 5 seconds

        In this case, no response from the server is good so timeouts are not raised to higher level
        handlers

        If there is a response, it is almost certainly an error. Parse to check
        If error, raise NetConfRPCError


        """
        self.logger.debug("NC Hello: Getting Server Hello from " + self.host)
        namespace = "{urn:ietf:params:xml:ns:netconf:base:1.0}"

        try:
            server_hello = self.rpexpect(MSG_DELIM)
            self.logger.info(server_hello)
            server_hello = _stripdelim(server_hello)
        except (nxos_XML_errors.TimeoutExpiredError, socket.timeout):
            exc_type, exc_value, exc_traceback = sys.exc_info()
            stacktrace = traceback.extract_tb(exc_traceback)
            self.logger.cricital("NC Hello: Timed Out Waiting for Hello from " + self.host)
            self.logger.debug(sys.exc_info())
            self.logger.debug(stacktrace)
            self.close()
            raise

        self.logger.debug(server_hello)
        self.logger.debug("NC Hello: Parsing the XML")
        try:
            root = etree.fromstring(server_hello)
        except:
            exc_type, exc_value, exc_traceback = sys.exc_info()
            stacktrace = traceback.extract_tb(exc_traceback)
            self.logger.critical("NC Hello: Failure parsing what should be the Hello from " + self.host)
            self.logger.debug(sys.exc_info())
            self.logger.debug(stacktrace)
            self.close()
            raise

        if 'hello' not in root.tag:
            self.logger.critical("NC Hello: Did not get hello from " + self.host)
            raise XMLError("Did not receive hello from " + self.host)
        capele = [i.text for i in root.iter() if 'capability' in i.tag]
        if len(capele):
            self.server_capabilities = capele
            self.logger.debug("NC Hello: Server Capabilities: {}".format(str(self.server_capabilities)))
        else:
            self.logger.critical("NC Hello: No capabilities in hello message from " + self.host)
            raise XMLError("Did not receive capabilities in the hello message from " + self.host)
        sessele = root.findall(".//" + namespace + "session-id")
        if len(sessele):
            self.sessionid = sessele[0].text
            self.logger.debug("NC Hello: Session ID {} from {}".format(str(self.sessionid), self.host))
        else:
            self.logger.critical("NC Hello: No session-id in the hello message from " + self.host)
            raise XMLError("Did not receive session-id in the hello message from " + self.host)

        self.logger.debug("NC Hello: Construct client hello for " + self.host)

        try:
            client_hello = buildclienthello()
            self.logger.debug("NC Hello: Constructed client hello message " + client_hello)
        except:
            exc_type, exc_value, exc_traceback = sys.exc_info()
            stacktrace = traceback.extract_tb(exc_traceback)
            self.logger.critical("NC Hello: Unable to construct client hello to send to " + self.host)
            self.logger.debug(sys.exc_info())
            self.logger.debug(stacktrace)
            raise

        self.logger.debug("NC Hello: Sending client hello to " + self.host)

        response = None
        savetimeout = self.command_timeout

        #nx-os does not reply to the client hello unless there is an error. This is annoying but compliant
        #with the RFC. To account for this, the command_timeout used by ncssh.rpexpect is reset to 5 seconds
        #this five seconds should probably be a global variable or it should be an instance variable made into a
        #property

        try:
            self.send(client_hello + MSG_DELIM)
            #should not see anything from server unless there is an error
            self.logger.debug("NC Hello: Current timeout is configured as " + str(self.command_timeout))
            self.logger.debug("NC Hello: Resetting Paramiko socket timeout to 1 second")
            self.command_timeout = 1
            response = self.rpexpect(MSG_DELIM, code=5)
        #A successful client hello should trigger no output from server, so look for socket timeout, which
        # is desirable in this case
        except (socket.timeout, nxos_XML_errors.TimeoutExpiredError):
            exc_type, exc_value, exc_traceback = sys.exc_info()
            stacktrace = traceback.extract_tb(exc_traceback)
            self.logger.info("NC Hello: Timeout sending client hello to " + self.host)
            self.logger.debug(sys.exc_info())
            self.logger.debug(stacktrace)
        except:
            exc_type, exc_value, exc_traceback = sys.exc_info()
            stacktrace = traceback.extract_tb(exc_traceback)
            self.logger.error("NC Hello: Unexpected error sending client hello to " + self.host)
            self.logger.debug(sys.exc_info())
            self.logger.debug(stacktrace)
            raise
        else:
            #if rpexpect returns successfully, we received a message from the server
            #it is probably an error message, so parse to check
            try:
                rpcparse(_stripdelim(response))
            except NetConfRPCError:
                exc_type, exc_value, exc_traceback = sys.exc_info()
                stacktrace = traceback.extract_tb(exc_traceback)
                self.logger.error("Error received from server after sending client hello to " + self.host)
                self.logger.debug(response)
                self.logger.debug(sys.exc_info())
                self.logger.debug(stacktrace)
                raise
        finally:
            self.logger.debug("Resetting Paramiko socket timeout to " + str(savetimeout))
            self.command_timeout = savetimeout
            self.logger.debug("Current timeout is configured as " + str(self.command_timeout))


    def _generaterpcmessageid(self):
        """
        Generates a random number to use as the starting message-id
        """
        self._rpcmessageid = random.randint(1, 1000000)

    @property
    def rpcmessageid(self):
        """

        @rtype : str
        @return: the rpc message id the client is currently using
        """
        if not self._useprovidedmessageid:
            rpcmessageid = str(self._rpcmessageid)
        else:
            rpcmessageid = self._rpcmessageid
        return rpcmessageid

    @rpcmessageid.setter
    def rpcmessageid(self, rpcmessageid):
        """

        @type rpcmessageid: str
        @param rpcmessageid: string to be used in next rpc message
        @return: None
        """
        assert isinstance(rpcmessageid, str) or rpcmessageid is None

        if rpcmessageid is None:
            if not self._useprovidedmessageid:
                self._rpcmessageid += 1
            else:
                self._useprovidedmessageid = False

        else:
            self._rpcmessageid = rpcmessageid
            self._useprovidedmessageid = True

    @netconfbuilder
    def nxosget(self, message, schema, getfilter="subtree"):
        """
        wraps xml string in appropriate rpc get and netconf tags and sends message to server

        -    @param schema: string which is the name of the nx-os schema to include in the get
        -    @param message: xml string to send to server, should be None if the get message is to be constructed from thethe filter
        -    @param getfilter:  can be None or a string indicating type (xpath or subtree)or a tuple of the form (type, filter)
        -    @return: the XML response from the server as a string or None if there is currently no ssh session to a server

        Examples:
        ::
        nxos_snippet="<show><vlan></vlan></show> "
        nxostest.nxosget(None, schema="vlan_mgr_cli", getfilter=("subtree", nxos_snippet))
        or
        nxostest.nxosget(nxos_snippet, schema="vlan_mgr_cli", getfilter="subtree")

        """

        self.logger.debug("Building rpc get to send to " + self.host)
        try:
            return buildnxosmessage('get', schema, str(self.rpcmessageid), message=message, ncfilter=getfilter)
        except:
            raise

    @netconfbuilder
    def nxoseditconfig(self, message, schema):
        """
        netconf edit-config. wraps message in appropriate RPC and netconf tags, sends message to server and
        returns reply from server

        @param schema: string with name of NX-OS schema
        @param message: NX-OS XML configuration

        @return: The XML output from the server as a string or None if there is currently no ssh session to a server.

        Example:
        ::
        CMD_VLAN_CONF_SNIPPET =" <configure>
        <__XML__MODE__exec_configure>
            <vlan>
              <vlan-id-create-delete>
                <__XML__PARAM_value>2000</__XML__PARAM_value>
                <__XML__MODE_vlan>
                  <name>
                    <vlan-name>TEST2000</vlan-name>
                  </name>
                </__XML__MODE_vlan>
              </vlan-id-create-delete>
            </vlan>
            </__XML__MODE__exec_configure>
        </configure>"

        ::
        nxostest.nxoseditconfig(CMD_VLAN_CONF_SNIPPET, schema="vlan_mgr_cli")

        """

        self.logger.debug("Building rpc get to send to " + self.host)
        try:
            return buildnxosmessage('edit-config', schema, str(self.rpcmessageid), message=message)
        except:
            raise

    @netconfbuilder
    def _closesession(self):
        """
        netconf close-session

        According to NX-OS documentation, the NX-OS server should return a Netconf ok, but in testing, this does
        not always occur. A NotConnectedError exception is raised if the channel closes without
        receiving an RPC ok. Wrap the closesession call in a try...except block

        @return: XML reply from server or None if there is currently no ssh session to a server

        """

        self.logger.debug("Building rpc close-session to send to " + self.host)
        try:
            nxosmessage = buildnxosmessage('close-session', None, str(self.rpcmessageid), message=None)
            self.logger.debug("NC: Close Session for {}: {}".format(self.host, nxosmessage))
            return nxosmessage
        except:
            raise

    def closesession(self):
        """
        Sends a netconf close

        @return:None
        """
        try:
            self._closesession()
        finally:
            self._ncconnected = False
            self.close()

    @netconfbuilder
    def killsession(self, sessionid):
        """
        netconf kill-session

        @param sessionid: session-id of the session to kill. You cannot kill your own session.
        @return: xml reply from the server or None if there is currently no ssh session to a server
        """
        self.logger.debug("Building rpc kill-session to send to " + self.host)
        try:
            return buildnxosmessage('kill-session', None, str(self.rpcmessageid), message=sessionid)
        except:
            raise

    @netconfbuilder
    def _nxoscli(self, clilist):
        """

        NX-OS <rpc> operation named <exec-command>

        @param clilist: list containing strings of commands; each string of command should be separated by a semicolon
        For example:

        ::
        clilist = ['conf t ; interface ethernet 2/1', 'channel-group 2000 ; no shut ']

        @return: XML reply from the server or None if there is currently no ssh session to a server

        """
        if isinstance(clilist, str):
            clilist = [clilist]
        self.logger.debug("Building rpc exec-command to send to " + self.host)
        try:
            return buildnxosclimessage(clilist, str(self.rpcmessageid))
        except:
            raise

    def send_xml_cli_conf(self, commands, no_end=True):
        """
        Method for sending configuration commands to the device
        @param commands: list of commands
        @param no_end: flag, if False, "end" is appended to the list of commands
        @return: None
        """
        if isinstance(commands, str):
            commands = [commands]
        else:
            commands = ["{}; ".format(' ; '.join(commands))]
        if not no_end:
            commands.append("end")
        self.logger.debug("Sending commands {} to {}".format(str(commands), self.host))
        try:
            return self._nxoscli(commands)
        except:
            raise

    def send_xml_cli_show(self, commands):
        """
        Method for sending a show command to the device
        @param commands: list of show commands or a string
        @return: string of xml output from the server
        """
        if isinstance(commands, str):
            commands = [commands]
        for i, command in enumerate(commands):
            self.logger.debug("send_xml_cli_show: Sending show command {} to {}".format(str(command), self.host))
            response = self._nxoscli(command)
            if i == 0:
                nsmap = response.nsmap
                result = etree.Element("result")
            self.logger.debug(result)
            self.logger.debug(nsmap)
            self.logger.debug(list(response))
            self.logger.debug(etree.tostring(list(response)[0], encoding='unicode',  pretty_print=True))
            result.append(list(response)[0])
        logger.debug(result)
        self.logger.debug("send_xml_cli_show: response from show commands {}".format(result))
        return result

    def _send(self, nxosmessage, rpcmessageid=None):

        """
        Send constructed client rpc message to server

        This method wraps the ncssh.send method and then waits for a response from the server using the ncssh.rpexpect method, which may return one of the following exceptions if there was a problem socket.timeout

        -    nxos_XML_errors.TimeoutExpiredError
        -    nxos_XML_errors.ServerClosedChannelError

        Any exceptions returned by ncssh.rpexpect are reraised

        Once the response is received, it is parsed to check for RPC error, NetConfRPCError, if detected, it is logged but not reraised.

        an lxml etree Element object is returned

        """

        #send message to server
        self.logger.debug("NC: Sending message to server {}: {}".format(self.host, nxosmessage + MSG_DELIM))
        self.send(nxosmessage + MSG_DELIM)

        #wait for response from server
        self.logger.debug("Waiting for response from server {} ".format(self.host))
        response = None
        try:
            response = self.rpexpect(MSG_DELIM)
            self.logger.debug("NC Send: message from server {}: {}".format(str(response), self.host))
        except socket.timeout:
            exc_type, exc_value, exc_traceback = sys.exc_info()
            stacktrace = traceback.extract_tb(exc_traceback)
            self.logger.error("Socket timeout waiting for response to rpc message {} to {}".format(nxosmessage, self.host))
            self.logger.debug("NC Send: receive message from server {}: {}".format(str(response), self.host))
            self.logger.debug(sys.exc_info())
            self.logger.debug(stacktrace)
            raise
        except nxos_XML_errors.TimeoutExpiredError:
            exc_type, exc_value, exc_traceback = sys.exc_info()
            stacktrace = traceback.extract_tb(exc_traceback)
            self.logger.error("Loop timeout waiting for response to rpc message {} to {}".format(nxosmessage, self.host))
            self.logger.debug("NC Send: receive message from server {}: {}".format(str(response), self.host))
            self.logger.debug(sys.exc_info())
            self.logger.debug(stacktrace)
            raise
        except nxos_XML_errors.ServerClosedChannelError:
            exc_type, exc_value, exc_traceback = sys.exc_info()
            stacktrace = traceback.extract_tb(exc_traceback)
            self.logger.error("Server closed channel while waiting for response to rpc message {} to {}".format(nxosmessage, self.host))
            self.logger.debug("NC Send: receive message from server {}: {}".format(str(response), self.host))
            self.logger.debug(sys.exc_info())
            self.logger.debug(stacktrace)
            self.closesession()
            #do not propagate exception, closesession will raise one
        except:
            exc_type, exc_value, exc_traceback = sys.exc_info()
            stacktrace = traceback.extract_tb(exc_traceback)
            self.logger.error("Unexpected error while waiting for response to rpc message {} to {}".format(nxosmessage, self.host))
            self.logger.debug("NC Send: receive message from server {}: {}".format(str(response), self.host))
            self.logger.debug(sys.exc_info())
            self.logger.debug(stacktrace)
            raise

        #parse response and check for errors
        self.logger.debug("NC Send: Parsing response from {}".format(self.host))
        try:
            response = _stripdelim(response)
            rpcparse(response, rpcmessageid=rpcmessageid)
        except NetConfRPCError:
            exc_type, exc_value, exc_traceback = sys.exc_info()
            stacktrace = traceback.extract_tb(exc_traceback)
            self.logger.critical("Error received from server after sending client message to " + self.host)
            self.logger.error(response)
            self.logger.error(sys.exc_info())
            self.logger.error(stacktrace)
            raise
        except nxos_XML_errors.NotConnectedError:
            exc_type, exc_value, exc_traceback = sys.exc_info()
            stacktrace = traceback.extract_tb(exc_traceback)
            self.logger.critical("Server {} indicates that session has timed out".format(self.host))
            self.logger.error(response)
            self.logger.error(sys.exc_info())
            self.logger.error(stacktrace)
            self.closesession()
            #do not propagate exception, closesession will raise one
        self.logger.info("Received response from " + self.host + ": " + response.decode())
        return etree.fromstring(response)

    def get_xmlxserverxtatus(self):
        """
        Gets the result of the "show xml server status" command from the nx-os switch

        @return: XML output of command or False if there is no connection to the server
        """
        if self.ncconnected:
            return self._nxoscli(['show xml server status'])
        else:
            return False

    @property
    def ncconnected(self):
        """

        Responds with the connection status of the netconf and ssh connections if the ncconected attribute is accessed

        """
        self._ncconnected = self.sshconnected
        return self._ncconnected

    def __enter__(self):
        self.logger.debug("Instantiating object via context management protocol")
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.closesession()
        if exc_type is None:
            self.logger.debug('exited context management normally')
        else:
            self.logger.error('Exception while exiting context management protocol! {0}'.format(str(exc_type)))
            self.logger.debug(exc_tb)
            return False    # Propagate


def _stripdelim(xmlstring):
    """
    str <- str
    Strip out the netconf message delim because it confuses the xml parsrer

    Takes an xml string and returns the same string without the netconf delimeter
    @param xmlstring:
    """

    return xmlstring[:xmlstring.find(MSG_DELIM.encode())]


if __name__ == "__main__":
    LOGFILE = "netconflog.log"
    LOGLEVEL = logging.DEBUG

    logger = logging.getLogger()
    logger.setLevel(LOGLEVEL)
    logformat = logging.Formatter('%(asctime)s: %(threadName)s - %(funcName)s - %(name)s - %(levelname)s - %(message)s')
    logh = logging.FileHandler(LOGFILE)
    logh.setLevel(LOGLEVEL)

    ch = logging.StreamHandler(stream=sys.stdout)
    ch.setLevel(logging.CRITICAL)

    logh.setFormatter(logformat)

    ch.setFormatter(logformat)

    logger.addHandler(logh)
    logger.addHandler(ch)

    logger.info("Started")

    nxostest = NxosConnect(host="172.16.1.166")
    print(nxostest.sshconnected)
    print(nxostest.ncconnected)
    nxostest.nc_sshconnect(username="cisco", password="cisco")
    print(nxostest.sshconnected)
    print(nxostest.ncconnected)
    nxos_snippet = """
      <show>
        <vlan>
          <id>
            <vlan-id>104</vlan-id>
          </id>
        </vlan>
      </show> """
    try:
        print(nxostest.nxosget(nxos_snippet, schema="vlan_mgr_cli", getfilter="subtree"))
    except:
        print("Got an error configuring vlan 104")
    try:
        print(nxostest.nxosget(None, schema="vlan_mgr_cli", getfilter=("subtree", nxos_snippet)))
    except:
        pass
    nxos_snippet = """
      <show>
        <vlan>
        </vlan>
      </show> """
    print(nxostest.nxosget(nxos_snippet, schema="vlan_mgr_cli", getfilter="subtree"))
    print("=============Show vlan commands=======================")
    print(nxostest._nxoscli(['show vlan id 1000']))
    print(nxostest._nxoscli(['show vlan']))

    CMD_VLAN_CONF_SNIPPET = """
    <configure>
          <__XML__MODE__exec_configure>
            <vlan>
              <vlan-id-create-delete>
                <__XML__PARAM_value>2100</__XML__PARAM_value>
                <__XML__MODE_vlan>
                  <name>
                    <vlan-name>TEST2100</vlan-name>
                  </name>
                </__XML__MODE_vlan>
              </vlan-id-create-delete>
            </vlan>
            </__XML__MODE__exec_configure>
        </configure>
"""
    try:
       print(nxostest.nxoseditconfig(CMD_VLAN_CONF_SNIPPET, schema="vlan_mgr_cli"))
    except:
        print("Got and Error configuring vlan")
    print(nxostest.get_xmlxserverxtatus())

    CMD_INT_STATUS_SNIPPET = """
      <show>
        <interface>
          <status>
          </status>
        </interface>
      </show>"""
    print(nxostest.nxosget(CMD_INT_STATUS_SNIPPET, schema="if_manager", getfilter="subtree"))

    CMD_INT_TRUNK_SNIPPET = """
      <show>
        <interface>
          <trunk>
          </trunk>
        </interface>
      </show>"""
    print(nxostest.nxosget(CMD_INT_TRUNK_SNIPPET, schema="if_manager", getfilter="subtree"))

    CMD_INT_VLAN = """
    <configure>
          <__XML__MODE__exec_configure>
          <interface>
            <ethernet>
              <interface>2/1</interface>
              <__XML__MODE_if-ethernet-switch>
                <switchport>
                  <trunk>
                    <allowed>
                      <vlan>
                        <add>
                           <vlan_id>2100</vlan_id>
                        </add>
                      </vlan>
                    </allowed>
                  </trunk>
                </switchport>
              </__XML__MODE_if-ethernet-switch>
            </ethernet>
          </interface>
          </__XML__MODE__exec_configure>
        </configure>
    """

    try:
        print(nxostest.nxoseditconfig(CMD_INT_VLAN, schema="if_manager"))
    except:
        print("Error configuring switchport vlan")

    print(nxostest.nxosget(CMD_INT_TRUNK_SNIPPET, schema="if_manager", getfilter="subtree"))

    # try:
    #     nxostest.closesession()
    # except:
    #     pass

    print()
    print("="*80)
    print("Printing vrf")
    print(etree.tostring(nxostest._nxoscli(['show vrf']), encoding='unicode',  pretty_print=True))
    print("Printing arp")
    print(etree.tostring(nxostest._nxoscli(['show ip arp']), encoding='unicode',  pretty_print=True))
    print("Print macs")
    print(etree.tostring(nxostest._nxoscli(['show mac address-table']), encoding='unicode',  pretty_print=True))
    print()
    print("="*80)
    print("All three commands")


    resp = nxostest.send_xml_cli_show(["show vrf", "show ip arp", "show mac address-table"])
    print(etree.tostring(strip_ns_prefix(resp), encoding='unicode',  pretty_print=True))
    print("=" * 80)

    nxostest.closesession()

    print("Closed")
    print(nxostest.ncconnected)
    print(nxostest.nxoseditconfig(CMD_VLAN_CONF_SNIPPET, schema="vlan_mgr_cli"))
    print(nxostest.get_xmlxserverxtatus())
