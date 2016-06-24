import json
import logging
from functools import wraps
from pprint import pprint
import time
#import xml.etree.ElementTree as ET
from lxml import etree as ET

import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning, HTTPError

from host import AnsibleHost
from netconf import NxosConnect

logger = logging.getLogger('hostsession')

class Host(AnsibleHost):
    """
       Session class
       This class is responsible for all communication with the switch.
    """
    def __init__(self, name, port=None):
        """
        :param name:  String containing the switch name
        :param port:  String containing port used to connect to switch
        """

        AnsibleHost.__init__(self, name, port)

    def _send_login(self, timeout=None):
        """
        Send the actual login request to the switch and open the web
        socket interface.
        """
        pass

    def login(self, timeout=None):
        """
        Initiate login to the switch.  Opens a communication session with the\
        switch using the python requests library.

        :returns: Response class instance from the requests library.\
        response.ok is True if login is successful.
        """
        pass

    def logged_in(self):
        """
        Returns whether the session is logged in to the switch

        :return: True or False. True if the session is logged in to the switch.
        """
        pass

    def refresh_login(self, timeout=None):
        """
        Refresh the login to the switch

        :param timeout: Integer containing the number of seconds for connection timeout
        :return: Instance of requests.Response
        """
        pass

    def run_commands(self, data, command_type='show', transport='nxapi', format='xml', secure=True, verify_ssl=False, timeout=None, port=None):
        """
        routes command to appropriate subsystem

        :param data: List of commands to send to the switch
        :param command_type: string, show or conf
        :param transport: string, nxapi or xss
        :param format: string indicating xml or json format, applicable only for nxapi
        :param secure: boolean secure, True means to use https, applicable only for nxapi
        :param verify_ssl: boolean verify_ssl, True means Requests verifies server certificate, applicable only for nxapi
        :param port:
        :raises: an error for invalid combination of command_type and transport
        """
        if port is not None:
            self.set_port(port)

        if (command_type == 'show' and transport == 'nxapi') or (command_type == 'conf' and transport == 'nxapi'):
            return self._nxapi(data, command_type, format, secure, verify_ssl, timeout)
        elif (command_type == 'show' and transport == 'xss') or (command_type == 'conf' and transport == 'xss'):
            return self._xss(data, command_type, timeout)
        else:
            raise SyntaxError("Combination of command_type {} and transport () is not supported".format(command_type, transport))

    def _nxapi(self, data, command_type, format, secure, verify_ssl, timeout):
        """
            Push the object data to the switch

            :param command_type: string show or conf
            :param data: List of commands to send to the switch
            :param format: string output type, xml or json
            :param secure: boolean True means https
            :param verify_ssl: boolean, Requests parameter
            :returns: json for json-rpc ET element object for xml
            """
        post_url = self._build_url(secure)
        myheaders, payload = self._nxapi_commands(data, format, command_type)
        logger.debug("_show: returned from _nxapi_commands: headers: {}, payload {}".format(myheaders, payload))
        logger.debug('Posting url: %s, headers: %s, payload: %s', post_url, myheaders, payload)

        resp = requests.post(post_url, data=payload,
                             headers=myheaders, auth=(self.vars['uid'], self.vars['pwd']),
                             verify=verify_ssl, timeout=timeout)
        logger.debug('Response: {}; Response Headers: {}; Text: {}'.format(resp, resp.headers, resp.text))
        if resp.status_code == requests.codes.ok:
            if 'json' in resp.headers['content-type']:
                return resp.json()
            else:
                logger.debug("XML")
                return ET.fromstring(resp.text)
        else:
            self.raise_for_status(resp)

    def raise_for_status(self, resp):
        """Raises stored :class:`HTTPError`, if one occurred."""

        http_error_msg = ''

        if 400 <= resp.status_code < 500:
            http_error_msg = '%s Client Error: %s for url: %s' % (resp.status_code, resp.reason, resp.url)

        elif 500 <= resp.status_code < 600:
            http_error_msg = '%s Server Error: %s for url: %s' % (resp.status_code, resp.reason, resp.url)

        if 'error' in resp.json():
            code = resp.json()['error']['code']
            message = resp.json()['error']['code']
            data = resp.json()['error']['data']
            http_error_msg = http_error_msg + "\n Switch Error Code: {}, Switch Error Message: {}, Switch Error Data: {}".format(code, message, data)

        if http_error_msg:
            raise HTTPError(http_error_msg, response=resp)

    def register_login_callback(self, callback_fn):
        """
        Register a callback function that will be called when the session performs a
        successful relogin attempt after disconnecting from the switch.

        :param callback_fn: function to be called
        """
        pass

    def deregister_login_callback(self, callback_fn):
        """
        Delete the registration of a callback function that was registered via the
        register_login_callback function.

        :param callback_fn: function to be deregistered
        """
        pass

    def invoke_login_callbacks(self):
        """
        Invoke registered callback functions when the session performs a
        successful relogin attempt after disconnecting from the switch.
        """
        pass

    def _build_url(self, secure):
        """
        builds url for nxapi

        :param secure: Boolean True means https
        :return: String url
        """
        if secure:
            url = "https://"
        else:
            url = "http://"
        url = url + self.name.strip()
        if self.vars['port']:
            url = url + ":{}".format(self.vars['port'])
        url = url + "/ins"
        return url

    def _nxapi_commands(self, data, format, type):
        """

        :param data: list of commands
        :param format: xml or json
        :param type: show or conf
        :return:
        """
        logger.debug("_nxapi_commands: data: {} format: {} type: {}".format(data, format, type))
        if format.strip().lower() == 'json':
            myheaders = {'content-type': 'application/json-rpc'}
            wrapper = {"jsonrpc": "2.0", "method": "cli",
                       "params": {"cmd": None,
                                  "version": 1},
                       "id": None
                       }
            payload = []
            for id, cmd in enumerate(data):
                payload.append(wrapper)
                payload[id]['params']['cmd'] = cmd
                payload[id]['id'] = id + 1
            payload = json.dumps(payload)
        elif format.strip().lower() == 'xml':
            myheaders = {'content-type': 'text/xml'}
            payload = """<?xml version="1.0"?>
                                    <ins_api>
                                    <version>1.2</version>
                                    <type>cli_{}</type>
                                     <chunk>0</chunk>
                                    <sid>sid</sid>
                                     <input>{}</input>
                                      <output_format>xml</output_format>
                                    </ins_api>"""
            if type == 'show':
                payload = payload.format(type, ' ;'.join(data))
            elif type == 'conf':
                payload = payload.format(type, ' ; '.join(data))
            else:
                raise ValueError("Unsupported type: {}".format(type))
        else:
            logger.critical("_show: Unsupported format. Must be xml or json")
            raise ValueError("Unsupported format: {}. Must be xml or json".format(format))
        logger.debug('_show headers: %s payload: %s', myheaders, payload)

        return myheaders, payload

    def _xss(self, data, command_type, timeout):
        """

        :param data: list of comands
        :param command_type: string, show or conf
        :param timeout:
        :return:
        """
        port = self.vars['port']
        logger.debug("port {}".format(port))
        if port is None:
            port = 22

        logger.debug("instantiating netconf object")
        nccswitch = NxosConnect(host=self.name)
        logger.debug("connecting to xml subsystem")
        nccswitch.nc_sshconnect(username=self.vars['uid'], password=self.vars['pwd'], timeout=timeout, port=port)
        if command_type == "show":
            logger.debug("sending show commands: {}".format(data))
            resp = nccswitch.send_xml_cli_show(data)
        elif command_type == "conf":
            logger.debug("sending configuration commands: {}".format(data))
            resp = nccswitch.send_xml_cli_conf(data)
        else:
            raise ValueError("Unsupported type: {}".format(type))
        logger.debug("Received lxml element object {}".format(resp))
        logger.debug("Closing xml session")
        nccswitch.closesession()
        logger.debug(nccswitch.ncconnected)
        return resp

    def set_port(self, port):
        """

        :param port:
        :return:
        """
        self.set_variable('port', int(port))

    def get_port(self):
        return self.vars['port']


class Switch(Host):
    """
    A wrapper for adding switch-specific methods and attributes
    """
    def __init__(self, *args, **kwargs):
        Host.__init__(self, *args, **kwargs)

if __name__ == '__main__':
    LOGFILE = "nxapi_cli" + time.strftime("_%y%m%d%H%M%S", time.gmtime()) + ".log"
    SCREENLOGLEVEL = logging.CRITICAL
    FILELOGLEVEL = logging.DEBUG
    logformat = logging.Formatter('%(asctime)s: %(threadName)s - %(funcName)s - %(name)s - %(levelname)s - %(message)s')

    logging.basicConfig(level=FILELOGLEVEL,
                        format='%(asctime)s: %(threadName)s - %(funcName)s - %(name)s - %(levelname)s - %(message)s',
                        filename=LOGFILE)

    # screen handler
    ch = logging.StreamHandler()
    ch.setLevel(SCREENLOGLEVEL)
    ch.setFormatter(logformat)

    logging.getLogger('').addHandler(ch)

    logger = logging.getLogger('session_test')

    logger.critical("Started")

    switch1 = Switch("172.16.1.166", port="8443")
    switch1.set_variable('uid', 'cisco')
    switch1.set_variable('pwd', 'cisco')
    print(switch1)
    resp = switch1.run_commands(data=['show version'], format='json')
    time.sleep(1)
    pprint(resp)

    resp = switch1.run_commands(data=['show version'], format='xml')
    time.sleep(1)
    ET.dump(resp)
    pprint(ET.tostringlist(resp))
    pprint(resp.findall(".//kickstart_ver_str")[0].text)

    resp = switch1.run_commands(data=['show vrf', 'show ip arp', 'show mac address-table'], format='xml')
    time.sleep(1)
    ET.dump(resp)
    print(ET.tostringlist(resp))

    print()
    print("=" * 80)
    print("Printing vrf")
    print(ET.tostring(switch1.run_commands(['show vrf'], transport='xss', port=22), encoding='unicode', pretty_print=True))
    print("Printing arp")
    print(ET.tostring(switch1.run_commands(['show ip arp'], transport='xss', port=22), encoding='unicode', pretty_print=True))
    print("Print macs")
    print(ET.tostring(switch1.run_commands(['show mac address-table'], transport='xss'), encoding='unicode', pretty_print=True))
    print()
    print("=" * 80)
    print("All three commands")
    print(ET.tostring(switch1.run_commands(["show vrf", "show ip arp", "show mac address-table"], transport='xss'),
                         encoding='unicode', pretty_print=True))
    print("=" * 80)

    print("Closed")