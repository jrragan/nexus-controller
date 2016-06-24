import concurrent.futures
import logging

import time

import sys
import traceback
from pprint import pprint

from group import Group
from ini import InventoryParser
from nxos_XML_errors import HostNotFoundError

logger = logging.getLogger('session')


class TaskThread(object):
    """

    """
    def run(self, apps_list, numthreads):
        """

        @param apps_list: a dictionary of dictionaries containg the app definitions to be run
        @param numthreads:
        @return: a dictionary of dictionaries with the form result[app][switch] = (success, result)
        """
        logger.debug(
            "TaskThread: apps_list {}, numthreads {}".format(apps_list, numthreads))
        results = {}
        logger.debug("Threadpool: {} threads".format(numthreads))
        with concurrent.futures.ThreadPoolExecutor(max_workers=numthreads) as executor:
            # Start the load operations and mark each future with its switch
            future_to_switches = {}
            try:
                for app, app_item in apps_list.items():
                    future_to_switches.update({
                        executor.submit(switch.run_commands, app_item['commands'], **app_item['kwargs']):
                            (switch, app) for switch in app_item['hosts']})
            except:
                exc_type, exc_value, exc_traceback = sys.exc_info()
                stacktrace = traceback.extract_tb(exc_traceback)
                logger.error(
                    "Error submitting tasks to thread pool")
                logger.debug(sys.exc_info())
                logger.debug(stacktrace)
                raise
            for future in concurrent.futures.as_completed(future_to_switches):
                switch, app = future_to_switches[future]
                if app not in results:
                    results[app] = {}
                try:
                    data = future.result()
                except Exception as exc:
                    exc_type, exc_value, exc_traceback = sys.exc_info()
                    stacktrace = traceback.extract_tb(exc_traceback)
                    logger.error(
                        '%r generated an exception: %s' % (switch.name, exc))
                    logger.debug(sys.exc_info())
                    logger.debug(stacktrace)
                    results[app][switch.name] = (False, exc)
                else:
                    results[app][switch.name] = (True, data)
        logger.debug("TaskThread: Results: {}".format(results))
        return results


class Controller(object):
    """
    Controller class container for multiple switches
    """

    def __init__(self):
        logger.debug("Controller Instantiated")
        self.groups = {'all': Group(name='all'), 'ungrouped': Group(name='ungrouped')}
        self.groups['all'].add_child_group(self.groups['ungrouped'])
        self.parser = InventoryParser(self.groups)
        self.apps = {}
        self.num_hosts = 0

    def add_switch(self, device, uid, pwd, group='ungrouped'):
        """

        :param device: IP or dns name of the device, can include port of form device:port
        :param uid: username string
        :param pwd:  password string
        :param group: ansible group string
        """
        line = ["{} uid={} pwd={}".format(device, uid, pwd)]
        logger.debug(line)
        try:
            self.parser.parse(line, start_group=group)
        except:
            exc_type, exc_value, exc_traceback = sys.exc_info()
            stacktrace = traceback.extract_tb(exc_traceback)
            logger.error(
                "Error loading switch {} into inventory".format(device))
            logger.debug(sys.exc_info())
            logger.debug(stacktrace)
            raise

    def add_group(self, group):
        """

        :param group: string - name of the group
        :return:
        """
        line = ["[{}]".format(group)]
        try:
            self.parser.parse(line)
        except:
            exc_type, exc_value, exc_traceback = sys.exc_info()
            stacktrace = traceback.extract_tb(exc_traceback)
            logger.error(
                "Error defining new group {} into inventory".format(group))
            logger.debug(sys.exc_info())
            logger.debug(stacktrace)
            raise

    def add_from_file(self, filename):
        """

        :param filename: string: inventory filename in ansible format
        :return:
        """
        try:
            self.parser.load_from_file(filename)
        except:
            exc_type, exc_value, exc_traceback = sys.exc_info()
            stacktrace = traceback.extract_tb(exc_traceback)
            logger.error(
                "Error loading inventory from file {}".format(filename))
            logger.debug(sys.exc_info())
            logger.debug(stacktrace)
            raise

    def set_app(self, name, commands, hosts='all', command_type='show', transport='xss', format='xml', secure=True,
            verify_ssl=False, timeout=None, port=None, uid=None, pwd=None):
        """

        Method for defining apps

        @param name: string, name of the app
        @param commands: list of commands you wish to run on the devices
        @param hosts: can be an ansible group, a list of switches already in the inventory or a single switch either in or not in the inventory
        @param command_type: show or conf, default is show
        @param transport: nxapi or xml subsystem (xss), xss is the default
        @param format: xml or json, xml is the default
        @param secure: boolean, only applies to nxapi, True means https
        @param verify_ssl: boolean, only applies to nxapi, True means certificates are validated
        @param timeout: integer
        @param port: integer, default is 80 for http, 443 for https and 22 for netconf over ssh
        @param uid: string, username if hosts is a device not already in the inventory
        @param pwd: string, password if hosts is a device not already in the inventory
        @return: if parser and display functions are not provided, returns either json or an lxml Element object, if one
        or both of the parser and display functions are provided, it returns the result of the function(s)
        """
        logger.debug(
            "app: name {}, commands {}, hosts {}, command_type {}, transport {}, format {}, secure {}, verify_ssl {}, timeout {}, port {}, uid {}, pwd {}".format(
                name,
                commands,
                hosts, command_type,
                transport,
                format,
                secure,
                verify_ssl,
                timeout,
                port, uid,
                pwd))
        logger.debug("groups: {}".format(self.groups))
        logger.debug("all hosts: {}".format(self.groups['all'].get_hosts()))
        if hosts in self.groups:
            logger.debug("host is a group {} {}".format(hosts, self.groups))
            host_list = self.groups[hosts].get_hosts()
        elif isinstance(hosts, str):
            logger.debug("hosts is a single host {}".format(hosts))
            if hosts not in self.parser.hosts:
                self.add_switch(hosts, uid, pwd)
            elif hosts in self.parser.hosts and (uid is not None or pwd is not None):
                self.parser.hosts[hosts].set_variable('uid', uid)
                self.parser.hosts[hosts].set_variable('pwd', pwd)
            host_list = [self.parser.hosts[hosts]]
        elif (isinstance(hosts, list) or isinstance(hosts, tuple)):
            logger.debug("hosts is a list of hosts {}".format(hosts))
            host_list = []
            for host in hosts:
                if host not in self.parser.hosts:
                    raise HostNotFoundError("Host {} not found".format(host))
                host_list.append(self.parser.hosts[host])
        else:
            raise HostNotFoundError("Hosts {} not found".format(hosts))

        self.apps[name] = {}
        self.apps[name]['hosts'] = host_list
        self.apps[name]['commands'] = commands
        self.apps[name]['kwargs'] = {'command_type': command_type,
                           'transport': transport, 'format': format, 'secure': secure,
                           'verify_ssl': verify_ssl, 'timeout': timeout, 'port': port}
        logger.debug("self.apps: {}".format(self.apps))


    def run_app(self, apps='all', parser=None, display=None, num_threads=1):
        """

        @param apps:
        @param parser:
        @param display:
        @param num_threads:
        @return:
        """
        apps_list = {}
        if isinstance(apps, str) and apps.strip().lower() == 'all':
            apps_list = self.apps.copy()
        elif isinstance(apps, str):
            apps_list[apps] = self.apps[apps]
        else:
            apps_list = { name : self.apps[name] for name in apps}

        num_hosts = 0
        for app in apps_list:
            num_hosts += len(apps_list[app]['hosts'])
        logger.debug("num_hosts {}".format(num_hosts))
        num_threads = min(num_threads, num_hosts)
        logger.debug("num_threads {}".format(num_threads))

        result = self._group_app(apps_list, num_threads)
        if parser is not None:
            logger.debug("Parsing")
            result = parser(result)
            logger.debug("parser {} result {}".format(parser, result))
        if display is not None:
            logger.debug("Displaying")
            result = display(result)
            logger.debug("display {} result {}".format(display, result))
        return result

    def _group_app(self, apps_list, numthreads):
        """

        @param apps_list:
        @param numthreads:
        @return:
        """

        logger.debug(
            "group_app: apps_list {}, numthreads {}".format(apps_list, numthreads))
        try:
            tasker = TaskThread()
            result = tasker.run(apps_list, numthreads)
        except:
            exc_type, exc_value, exc_traceback = sys.exc_info()
            stacktrace = traceback.extract_tb(exc_traceback)
            logger.error(
                "Error in tasker")
            logger.debug(sys.exc_info())
            logger.debug(stacktrace)
            raise
        return result

    def clear_apps(self):
        self.apps.clear()

    def clear_hosts(self):
        del self.parser
        self.groups = {'all': Group(name='all'), 'ungrouped': Group(name='ungrouped')}
        self.groups['all'].add_child_group(self.groups['ungrouped'])
        self.parser = InventoryParser(self.groups)

    def remove_app(self, app):
        try:
            del self.apps[app]
        except KeyError:
            pass

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

    logger = logging.getLogger('controller_test')

    logger.critical("Started")

    from lxml import etree as ET

    def display_result(result):
        pprint(result)
        for key, inner in result.items():
            print(key)
            for switch, value in inner.items():
                print(switch)
                if value[0]:
                   print(ET.tostring(value[1], encoding='unicode', pretty_print=True))
                else:
                    print("Error: {}".format(value[1]))

    def run_controller(controller, transport='xss', port=22, numthreads=1):
        controller.clear_apps()
        print()
        print("=" * 80)
        print("Printing vrf")
        start = time.time()
        controller.set_app('showvrf', ['show vrf'], transport=transport, port=port)
        result = controller.run_app('showvrf', num_threads=numthreads)
        print("total time : {}".format(time.time() - start))
        display_result(result)
        print("Printing arp")
        start = time.time()
        controller.set_app('showarp', ['show ip arp'], transport=transport, port=port)
        result = controller.run_app('showarp', num_threads=numthreads)
        print("total time : {}".format(time.time() - start))
        display_result(result)
        print("Print macs")
        start = time.time()
        controller.set_app('showmac', ['show mac address-table'], transport=transport, port=port)
        result = controller.run_app('showmac', num_threads=numthreads)
        print("total time : {}".format(time.time() - start))
        display_result(result)
        print()
        print("=" * 80)
        print("All three commands")
        start = time.time()
        controller.set_app('show3', ["show vrf", "show ip arp vrf all", "show mac address-table"], transport=transport, port=port)
        result = controller.run_app('show3', num_threads=numthreads)
        print("total time : {}".format(time.time() - start))
        display_result(result)
        print("=" * 80)


    controller = Controller()
    print("One Switch")
    controller.add_switch("172.16.1.191", "cisco", "cisco")
    run_controller(controller)
    print("Add second switch")
    controller.add_switch("172.16.1.194", "cisco", "cisco")
    run_controller(controller)
    print("increase thread count")
    run_controller(controller, numthreads=2)
    print("try nxapi")
    run_controller(controller, transport='nxapi', port=8443, numthreads=2)
    print("Closed")
