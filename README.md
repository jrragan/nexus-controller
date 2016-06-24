# nexus-controller

Requires Python 3.2+, lxml, Paramiko and Requests

This library allows one to connect to and run commands on a Nexus using either nx-api or netconf.

## Example of using the Controller class

First instantiate the class and add switches to the controller's inventory. You can also use the Controller's 'add_from_file' to load the inventory from an ansible host file. 

```
controller = Controller()
controller.add_switch("172.16.1.191", "cisco", "cisco")
controller.add_switch("172.16.1.194", "cisco", "cisco")
```
Add apps to the controller. An app is a list of commands to run on a subset of the inventory. Multiple apps can be run at once.

```
controller.set_app('show3', ["show vrf", "show ip arp vrf all", "show mac address-table"], transport=transport, port=port)
result = controller.run_app('show3', num_threads=2)
```

The 'run_app' method will takes the name of the app or apps you wish to run and the number of threads you wish to use. Either a dictionary of lxml Element objects is returned or a dictionary of JSON objects (python dictionaries). The format of the lxml Element dictionary is {app_name : {switch_name : (success, combined xml of outputs)}}. 

For example

```
{'show3': {'172.16.1.247': (True, <Element result at 0x28c0a6f6748>),
           '172.16.1.248': (True, <Element result at 0x28c0a6f6948>),
           '172.16.1.249': (True, <Element result at 0x28c0a6f9488>)}}
```
           
If the commands failed,

```
{'show3': {'172.16.1.247': (False,
                            ConnectionError(MaxRetryError("HTTPSConnectionPool(host='172.16.1.247', port=8443): Max retries exceeded with url: /ins (Caused by NewConnectionError('<requests.packages.urllib3.connection.VerifiedHTTPSConnection object at 0x0000028C09E0FAC8>: Failed to establish a new connection: [WinError 10061] No connection could be made because the target machine actively refused it',))",),)),
           '172.16.1.248': (False,
                            ConnectionError(MaxRetryError("HTTPSConnectionPool(host='172.16.1.248', port=8443): Max retries exceeded with url: /ins (Caused by NewConnectionError('<requests.packages.urllib3.connection.VerifiedHTTPSConnection object at 0x0000028C0A6BE080>: Failed to establish a new connection: [WinError 10061] No connection could be made because the target machine actively refused it',))",),)),
           '172.16.1.249': (False,
                            ConnectionError(MaxRetryError("HTTPSConnectionPool(host='172.16.1.249', port=8443): Max retries exceeded with url: /ins (Caused by NewConnectionError('<requests.packages.urllib3.connection.VerifiedHTTPSConnection object at 0x0000028C0A6DC240>: Failed to establish a new connection: [WinError 10061] No connection could be made because the target machine actively refused it',))",),))}}
```

##Controller class

```
add_switch(self, device, uid, pwd, group='ungrouped'):
        """

        :param device: IP or dns name of the device, can include port of form device:port
        :param uid: username string
        :param pwd:  password string
        :param group: ansible group string
        """

add_group(self, group):
        """

        :param group: string - name of the group
        :return:
        """
        
add_from_file(self, filename):
        """

        :param filename: string: inventory filename in ansible format
        :return:
        """
        
set_app(self, name, commands, hosts='all', command_type='show', transport='xss', format='xml', secure=True,
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
        
run_app(self, apps='all', parser=None, display=None, num_threads=1):
        """

        @param apps:
        @param parser:
        @param display:
        @param num_threads:
        @return:
        """
```
##Example of an application using the Controller

An app that goes out to each switch in the inventory and produces a list of endpoints known to the fabirc. See endpoints.py for the app.

```
endpoints([('172.16.1.247', 'cisco', 'cisco'), ('172.16.1.248', 'cisco', 'cisco'), ('172.16.1.249', 'cisco', 'cisco')])

```

This outputs:

```
MAC                    SWITCH                    IP                     VRF            INTERFACE      VLAN       SECURE     STATIC    
fa16.3e97.f7fb         172.16.1.249              10.0.0.3               default        Vlan200                                        
fa16.3eef.b9e2         172.16.1.248              10.0.0.30              default        Ethernet2/4                                    
fa16.3e3e.c902         172.16.1.247              10.0.0.12              default        Ethernet2/2                                    
fa16.3e7d.1880         172.16.1.248              10.0.0.17              default        Ethernet2/3                                    
fa16.3e00.0006         172.16.1.249              10.10.0.1              default        Vlan100                                        
                       172.16.1.247              10.10.0.1              default        Ethernet2/1                                    
fa16.3ef9.5655         172.16.1.247                                                    sup-eth1(R)    0          disabled   enabled   
fa16.3ee7.fddd         172.16.1.249              10.20.0.10             default        Vlan300                                        
9a47.4451.fcdb         172.16.1.248              172.16.1.245           management     mgmt0                                          
                       172.16.1.249              172.16.1.245           management     mgmt0                                          
                       172.16.1.247              172.16.1.245           management     mgmt0                                          
0050.56c0.0002         172.16.1.248              172.16.1.1             management     mgmt0                                          
                       172.16.1.249              172.16.1.1             management     mgmt0                                          
                       172.16.1.247              172.16.1.1             management     mgmt0                                          
fa16.3ece.b757         172.16.1.247              10.0.0.10              default        Ethernet2/2                                    
fa16.3e0f.9e81         172.16.1.249              10.20.0.6              default        Vlan300                                        
fa16.3e62.ed56         172.16.1.247              10.0.0.11              default        Ethernet2/2                                    
fa16.3e00.0001         172.16.1.248              10.10.0.25             default        Ethernet2/1                                    
                       172.16.1.249              10.10.0.25             default        Vlan100                                        
fa16.3ef7.95c5         172.16.1.249                                                    sup-eth1(R)    0          disabled   enabled   
fa16.3ef7.95c5         172.16.1.249                                                    sup-eth1(R)    300        disabled   enabled   
fa16.3ef7.95c5         172.16.1.249                                                    sup-eth1(R)    100        disabled   enabled   
fa16.3ef7.95c5         172.16.1.249                                                    sup-eth1(R)    200        disabled   enabled   
                       172.16.1.248              10.10.0.22             default        Ethernet2/1                                    
                       172.16.1.247              10.10.0.22             default        Ethernet2/1                                    
fa16.3edf.e547         172.16.1.249              10.0.0.1               default        Vlan200                                        
fa16.3e88.cb6f         172.16.1.248                                                    sup-eth1(R)    0          disabled   enabled   
```
