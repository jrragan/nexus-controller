import logging

import time
from pprint import pprint

from lxml import etree as ET

from controller import Controller
from nxosXmlFunctions import parse_get_nsmap, parse_xml_heirarchy
from xmlFunctions import strip_ns_prefix


class EndPoints(object):
    def __init__(self, controller, hosts):
        self.controller = controller
        self.hosts = hosts
        self.vrf_command = ['show vrf']
        self.mac_command = ['show mac address-table']
        self._get_arp_commands()
        self._get_ips()

    def _get_arp_commands(self):
        self.vrfs = {}
        self.macs = {}
        self.controller.set_app('arp', self.vrf_command + self.mac_command, hosts=self.hosts)
        result = self.controller.run_app('arp')
        for key, value in result['arp'].items():
            if value[0]:
                xssparsed = strip_ns_prefix(value[1])
                xssschema = parse_get_nsmap(xssparsed)
                self._get_vrfs(key, xssparsed, xssschema)
                self._get_macs(key, xssparsed, xssschema)
            else:
                print("Error: {}".format(value[1]))
        logger.debug("self.vrfs {}".format(self.vrfs))
        self.controller.clear_apps()
        for key, value in self.vrfs.items():
            logger.debug("key {} value {}".format(key, value))
            self.controller.set_app(key, ["show ip arp vrf {}".format(vrf) for vrf in value], hosts=key )

    def _get_vrfs(self, key, xssparsed, xssschema):
        print(xssschema)
        xssvrf = parse_xml_heirarchy('ROW_vrf', 'vrf_name', xssschema, xssparsed)
        self.vrfs[key] = []
        for vrfdict in xssvrf:
            self.vrfs[key].append(vrfdict['vrf_name'])

    def _get_macs(self, key, xssparsed, xssschema):
        xssmac = parse_xml_heirarchy('ROW_mac_address', ['disp_mac_addr', 'disp_vlan', 'disp_is_static',
                                                         'disp_age', 'disp_is_secure', 'disp_port'], xssschema, xssparsed)
        logger.debug("xssmac {}".format(xssmac))
        for macdict in xssmac:
            logger.debug("macdict {} ".format(macdict))
            maccopy = macdict.copy()
            mac = maccopy.pop('disp_mac_addr')
            maccopy['switch'] = key
            if mac in self.macs:
                self.macs[mac]['l2'].append(maccopy)
            else:
                self.macs[mac] = {}
                self.macs[mac]['l2'] = [maccopy]

    def _get_ips(self):
        logger.debug("self.vrfs {} {}".format(self.vrfs.keys(), self.vrfs))
        result = self.controller.run_app(num_threads=len(self.vrfs.keys()))
        #returns a dictionary of form {app_name: {switch_name : Element}}
        self.controller.clear_apps()
        for key, switch in result.items():
            for name, value in switch.items():
                if value[0]:
                    xssparsed = strip_ns_prefix(value[1])
                    xssschema = parse_get_nsmap(xssparsed)
                    self._parse_ips(key, xssparsed, xssschema)
                else:
                    print("Error: {}".format(value[1]))
        pprint(self.macs)

    def _parse_ips(self, key, xssparsed, xssschema):
        logger.debug("xssparsed {}".format(ET.tostring(xssparsed, pretty_print=True)))
        #parse the Element object for each vrf
        for vrf in self.vrfs[key]:
            logger.debug("vrf {}".format(vrf))
            find = xssparsed.find(".//ROW_vrf[vrf-name-out='{}']/TABLE_adj".format(vrf.strip().lower()))
            logger.debug("find {}".format(find))
            #returns a list of Element objects
            #parse each element object to get a list of dictionaries of interesting data
            for element in find:
                logger.debug("element {}".format(element))
                xssarp = parse_xml_heirarchy('ROW_adj', ['intf-out', 'ip-addr-out', 'time-stamp',
                                                                 'mac'], xssschema, element)
                logger.debug("xssarp {}".format(xssarp))
                #this returns a list of dictionaries, one element for each ROW_adj entry
                for aentry in xssarp:
                    aecopy = aentry.copy()
                    mac = aentry['mac']
                    del aecopy['mac']
                    aecopy['vrf'] = vrf
                    aecopy['switch'] = key
                    if mac in self.macs and 'l3' not in self.macs[mac]:
                        self.macs[mac]['l3'] = []
                    elif mac not in self.macs:
                        self.macs[mac] = {}
                        self.macs[mac]['l3'] = []
                    self.macs[mac]['l3'].append(aecopy)

    def __str__(self):
        str_obj = "{:<22} {:<25} {:<22} {:<14} {:<14} {:<10} {:<10} {:<10}".format("MAC", "SWITCH", "IP", "VRF", "INTERFACE", "VLAN", "SECURE", "STATIC")
        for mac, mac_dict in self.macs.items():
            flag = True
            if 'l2' in mac_dict:
                str_obj = str_obj + "\n{:<22} {:<25} {:<22} {:<14} {:<14} {:<10} {:<10} {:<10}".format(mac, mac_dict['l2'][0]['switch'],
                                                                                                            '',
                                                                                                            '',
                                                                                                            mac_dict['l2'][0]['disp_port'],
                                                                                                            mac_dict['l2'][0]['disp_vlan'],
                                                                                                            mac_dict['l2'][0]['disp_is_secure'],
                                                                                                            mac_dict['l2'][0]['disp_is_static'])
                for l2dict in mac_dict['l2'][1:]:
                    str_obj = str_obj + "\n{:<22} {:<25} {:<22} {:<14} {:<14} {:<10} {:<10} {:<10}".format(mac, l2dict['switch'],
                                                                                                    '',
                                                                                                    '',
                                                                                                    l2dict['disp_port'],
                                                                                                     l2dict['disp_vlan'],
                                                                                                     l2dict['disp_is_secure'],
                                                                                                     l2dict['disp_is_static'])
            else:
                str_obj = str_obj + "\n{:<22} {:<25} {:<22} {:<14} {:<14} {:<10} {:<10} {:<10}".format(mac, mac_dict['l3'][0]['switch'],
                                                                                                            mac_dict['l3'][0]['ip-addr-out'],
                                                                                                            mac_dict['l3'][0]['vrf'],
                                                                                                            mac_dict['l3'][0]['intf-out'],
                                                                                                            '',
                                                                                                            '',
                                                                                                            '')
                flag = False
            if 'l3' in mac_dict:
                if flag:
                    l3list = mac_dict['l3'][:]
                else:
                    l3list = mac_dict['l3'][1:]
                for l3dict in l3list:
                    str_obj = str_obj + "\n{:<22} {:<25} {:<22} {:<14} {:<14} {:<10} {:<10} {:<10}".format('',
                                                                                                              l3dict['switch'],
                                                                                                              l3dict['ip-addr-out'],
                                                                                                              l3dict['vrf'],
                                                                                                              l3dict['intf-out'],
                                                                                                              '',
                                                                                                              '',
                                                                                                              '')

        return str_obj

def endpoints(hosts):
    """

    @param hosts: list of tuples [(switch, uid, pwd}]
    @return:
    """
    controller = Controller()
    for switch, uid, pwd in hosts:
        controller.add_switch(switch, uid, pwd)
    endpoints = EndPoints(controller, hosts='all')
    print(endpoints)

if __name__ == '__main__':
    LOGFILE = "controller" + time.strftime("_%y%m%d%H%M%S", time.gmtime()) + ".log"
    SCREENLOGLEVEL = logging.DEBUG
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

    logger = logging.getLogger('endpoints_test')

    logger.critical("Started")
    endpoints([('172.16.1.247', 'cisco', 'cisco'), ('172.16.1.248', 'cisco', 'cisco'), ('172.16.1.249', 'cisco', 'cisco')])
