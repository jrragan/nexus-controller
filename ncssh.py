import threading

__version__ = '2016.06.12.1'

"""
4/5/14 - logging changes in rpexcept method
3/24/14 - Minor changes to logging in rpexcept method
2/28/14 - Change to compensate for a bug in some versions of Paramiko
6/12/16 - rewrote known_hosts file handling
"""

import abc
import functools
import getpass
import logging
import os
import re
import socket
import sys
import time
import traceback

import paramiko

from nxos_XML_errors import TimeoutExpiredError, ServerClosedChannelError, NotConnectedError

# Static Variables, global for now

DEBUG = False
KEYFILE = "paramikolocalhostkeys"
LOGFILE = "netconflog.log"
LOGLEVEL = logging.DEBUG

# Set up the logger - I love me some loggers

logger = logging.getLogger('ncssh')

logger.info("Starting SSH")


def checkconnection(func):
    @functools.wraps(func)
    def decorator(self, *args, **kwargs):
        self.logger.debug('checkconnection: instance %s of class %s is now decorated with checkconnection, whee!' % (
            self, self.__class__))
        if not self.sshconnected:
            self.logger.error(
                "checkconnection: The ssh connection to {} is currently closed. Please reconnect and try again.".format(
                    self.host))
            raise NotConnectedError(
                "The ssh connection to {} is currently closed. Please reconnect and try again.".format(self.host))
        else:
            try:
                result = func(self, *args, **kwargs)
            except:
                exc_type, exc_value, exc_traceback = sys.exc_info()
                stacktrace = traceback.extract_tb(exc_traceback)
                self.logger.debug("checkconnection: Error with the SSH message")
                self.logger.debug(sys.exc_info())
                self.logger.debug(stacktrace)
                raise
            else:
                return result

    return decorator


class SshConnect(object):
    """
    Sets Up SSH v2 Session 
    """

    #----------------------------------------------------------------------
    def __init__(self, host):

        """
        Initialize ssh object
        *host* is the hostname or IP address to connect to
        @param host: str

        """

        self.logger = logging.getLogger('ncssh.SshConnect')

        self.host = host

        self.logger.debug("Creating SSH Cliet Object for " + self.host)

        self._transport = None
        self._sshconnected = False

        self.known_hosts = None


    def sshconnect(self, port=22, timeout=None, unknown_host_cb='autoaddpolicy',
                   username=None, password=None, host_key_filename=None, key_filename=None, allow_agent=True,
                   look_for_keys=False, command_timeout=30, **kwargs):
        """
        Connect via SSH and initialize a session. First attempts the publickey
        authentication method and then password authentication.

        To disable attempting publickey authentication altogether, call with
         *allow_agent* and *look_for_keys* as `False`.

        Must be called with the following options:

        -    *port* is by default 22

        -    *timeout* is an optional timeout for socket connect

        -    *unknown_host_cb* is called when the server host key is not recognized. It takes two arguments, the hostname and the fingerprint (see the signature of :func:`default_unknown_host_cb`)

        -    *username* is the username to use for SSH authentication

        -    *password* is the password used if using password authentication, or the passphrase to use for unlocking keys that require it

        -    *host_key_filename* is a filename where the host keys are located. If *filename* is not specified, looks in the default locations i.e. :file:`~/.ssh/known_hosts` and :file:`~/ssh/known_hosts` for Windows

        -    *key_filename* is a filename where a the private key to be used can be found

        -    *allow_agent* enables querying SSH agent (if found) for keys

        -    *look_for_keys* enables looking in the usual locations for ssh keys (e.g. :file:`~/.ssh/id_*`)

        -    *command_timeout* time in seconds to wait for expected output from server, default is 30 seconds


        -    @type port: int
        -    @type timeout: float
        -    @type username: str
        -    @type password: str
        -    @type unknown_host_cb: str
        -    @type host_key_filename: str
        -    @type key_filename: str
        -    @type allow_agent: bool
        -    @type look_for_keys: bool
        -    @type command_timeout: float

        This method relies on the self.setup_channel method for defining the channel characteristics
        This is defined as an abstract method
        Since there are multiple channel options, it is up to the subclass to define this method, probably using the ssh_subsystem method or the ssh_shell method

        For example the subclass could define the method as

        ::

            def setup_channel():
                self.ssh_subsystem('xmlagent')

        """

        self.port = port
        self.timeout = timeout
        self.username = username
        self.password = password
        self.unknown_host_cb = unknown_host_cb
        self.host_key_filename = host_key_filename
        self.key_filename = key_filename
        self.allow_agent = allow_agent
        self.look_for_keys = look_for_keys
        self._command_timeout = command_timeout
        self.ssh_client = None
        self._transport = None
        self._sshconnected = False
        self._channel = None

        if self.username is None:
            self.username = getpass.getuser()
        if self.password is None:
            self.password = getpass.getpass("Enter password for " + self.username + " :  ")

        self.logger.debug("Creating SSH connection to " + self.host)

        self.ssh_object()
        self.logger.debug("SSH object instantiated")
        self.ssh_client.set_log_channel(self.logger.name)
        self.ssh_connect()
        self.logger.debug("Connected to host " + self.host)
        self.logger.debug("Setting up channel to {}".format(self.host))

        #The setup_channel method is abstract and Must be defined by a subclass
        self.setup_channel()
        if self._transport.is_active() and self._transport.is_authenticated():
            self._sshconnected = True

        socket.setdefaulttimeout(self.command_timeout + 30.0)


    def ssh_object(self):
        """
        Instantiates Paramiko SSH Cliet object and Configures Host Key Policy
        """
        try:
            self.logger.debug("Instantiating Paramiko SSH Client Object for connecting to " + self.host)
            self.ssh_client = paramiko.SSHClient()
        except:
            exc_type, exc_value, exc_traceback = sys.exc_info()
            stacktrace = traceback.extract_tb(exc_traceback)
            self.logger.critical("Error creating SSH object for host " + self.host)
            self.logger.debug(sys.exc_info())
            self.logger.debug(stacktrace)
            raise
        if self.unknown_host_cb.lower() == 'autoaddpolicy':
            self.ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        elif self.unknown_host_cb.lower() == 'warningpolicy':
            self.ssh_client.set_missing_host_key_policy(paramiko.WarningPolicy())
        elif self.unknown_host_cb.lower() == 'rejectpolicy':
            self.ssh_client.set_missing_host_key_policy(paramiko.RejectPolicy())
        else:
            self.logger.critical("Unsupported Unknown Host Policy for " + self.host)
            raise NotImplementedError
        self.logger.debug("Looking for system known_hosts keys file for " + self.host)
        if self.host_key_filename is None and sys.platform.startswith('win'):
            if os.path.exists(os.path.join(os.environ.get('ProgramFiles'), 'OpenSSH', 'bin', 'ssh', 'known_hosts')):
                knownhostfile = os.path.join(os.environ.get('ProgramFiles'), 'OpenSSH', 'bin', 'ssh', 'known_hosts')
            elif os.path.exists(os.path.join(os.environ.get('ProgramFiles(x86)'), 'OpenSSH', 'bin', 'ssh', 'known_hosts')):
                knownhostfile = os.path.join(os.environ.get('ProgramFiles(x86)'), 'OpenSSH', 'bin', 'ssh', 'known_hosts')
            elif os.path.exists(os.path.join(os.environ.get('USERPROFILE'), 'ssh', 'known_hosts')):
                knownhostfile = os.path.join(os.environ.get('USERPROFILE'), 'ssh', 'known_hosts')
            elif os.path.exists(os.path.join(os.environ.get('USERPROFILE'), '.ssh', 'known_hosts')):
                knownhostfile = os.path.join(os.environ.get('USERPROFILE'), '.ssh', 'known_hosts')
            else:
                knownhostfile = os.path.join(os.environ.get('USERPROFILE'), 'ssh', 'known_hosts')
                if not os.path.exists(os.path.join(os.environ.get('USERPROFILE'), 'ssh')):
                    try:
                        os.makedirs(os.path.join(os.environ.get('USERPROFILE'), 'ssh'))
                    except OSError:
                        pass
                with open(knownhostfile, 'w') as khf:
                    pass
        elif self.host_key_filename is None:
            knownhostfile = os.path.expanduser('~/.ssh/known_hosts')
            if not os.path.exists(os.path.expanduser('~/.ssh/known_hosts')):
                try:
                    os.makedirs(os.path.join(os.path.expanduser('~/.ssh/known_hosts')))
                except OSError:
                    pass
            with open(knownhostfile, 'w') as khf:
                pass
        else:
            knownhostfile = self.host_key_filename
        try:
            self.ssh_client.load_host_keys(knownhostfile)
        except IOError:
            exc_type, exc_value, exc_traceback = sys.exc_info()
            stacktrace = traceback.extract_tb(exc_traceback)
            self.logger.critical("Unable to open system host keys file for " + self.host)
            self.logger.debug(sys.exc_info())
            self.logger.debug(stacktrace)
            raise

    def ssh_connect(self):
        """
        Connect to SSH Server

        If connection is unsuccessful, one of the following exceptions may be raised

        socket.gaierror     will be raised if the DNS lookup fails
        socket.error        will be raised if there is a TCP/IP problem
        paramiko.AuthenticationException        will be raised if SSH authentication fails
        """

        try:
            self.logger.debug("Opening Connection to " + self.host)
            self.ssh_client.connect(self.host, port=self.port, timeout=self.timeout, username=self.username,
                                        password=self.password,
                                        key_filename=self.key_filename, allow_agent=self.allow_agent,
                                        look_for_keys=self.look_for_keys)
        except socket.gaierror:
            exc_type, exc_value, exc_traceback = sys.exc_info()
            stacktrace = traceback.extract_tb(exc_traceback)
            self.logger.critical("Connection Failure for " + self.host + ":  DNS Lookup Failure")
            self.logger.debug(sys.exc_info())
            self.logger.debug(stacktrace)
            self.ssh_client.close()
            raise
        except socket.error:
            exc_type, exc_value, exc_traceback = sys.exc_info()
            stacktrace = traceback.extract_tb(exc_traceback)
            self.logger.critical("Connection Failure for" + self.host + ":  Socket Error")
            self.logger.debug(sys.exc_info())
            self.logger.debug(stacktrace)
            self.ssh_client.close()
            raise
        except paramiko.AuthenticationException:
            exc_type, exc_value, exc_traceback = sys.exc_info()
            stacktrace = traceback.extract_tb(exc_traceback)
            self.logger.critical("Authentication Failure Accessing " + self.host)
            self.logger.debug(sys.exc_info())
            self.logger.debug(stacktrace)
            self.ssh_client.close()
            raise
        except:
            exc_type, exc_value, exc_traceback = sys.exc_info()
            stacktrace = traceback.extract_tb(exc_traceback)
            self.logger.critical("Connection Failure for " + self.host)
            self.logger.debug(sys.exc_info())
            self.logger.debug(stacktrace)
            self.ssh_client.close()
            raise

    @abc.abstractmethod
    def setup_channel(self):
        """Can't do much without a channel.
        Since there are multiple channel options, it is up to the subclass to define this method
        """

    def ssh_subsystem(self, subsystem):
        """
        Opens channel to SSH server connecting to the specified subsystem
        This would be the equivalent of the -s option from an ssh commandline
        @param subsystem: string indicating the subsystem

        Any exceptions will be logged and returned by a raise command to be caught by higher level
        exception handlers

        """

        self._subsystem = subsystem
        self.logger.debug("Opening channel to " + self.host + " and requesting the " + self._subsystem + " subsystem")
        try:
            self._transport = self.ssh_client.get_transport()
            self._channel = self._transport.open_session()
            self._channel.set_name(self._subsystem)
            self._channel.invoke_subsystem(self._subsystem)
        except:
            exc_type, exc_value, exc_traceback = sys.exc_info()
            stacktrace = traceback.extract_tb(exc_traceback)
            self.logger.critical("Failed to connect to " + self._subsystem + " subsystem on host " + self.host)
            self.logger.debug(sys.exc_info())
            self.logger.debug(stacktrace)
            raise

    def ssh_shell(self):
        """
        Opens an SSH shell on the server for interactive sessions

        @raise: Any exceptions will be logged and returned by a raise command to be caught by higher level
        exception handlers
        """

        self.logger.debug("Creating shell to " + self.host)
        try:
            self._transport = self.ssh_client.get_transport()
            self._channel = self.ssh_client.invoke_shell()
        except:
            exc_type, exc_value, exc_traceback = sys.exc_info()
            stacktrace = traceback.extract_tb(exc_traceback)
            self.logger.critical("Failure creating shell for " + self.host)
            self.logger.debug(sys.exc_info())
            self.logger.debug(stacktrace)
            raise

    @checkconnection
    def rpexpect(self, reguexp, code=4, characters=20):
        """

        Method to provide expect-like functionality

        str <- (str)

        -    code 0      Return specified number of characters at end of buffer
        -    code 1      Return specified number of characters at beginning of buffer
        -    code 2      Return TRUE if reguexp found, otherwise return false
        -    code 3      Return contents of buffer if regexp is found, else return false
        -    code 4      continually looks for reguexp in the buffer and returns contents of buffer if found,
                    if not found, times out.  This code must be used with paramiko.

        -    code = 5:  collect characters from channel until timeout is reached

        reguexp:    string representing the delimeter to look for in the channel

        Looks for the delimeter and returns the preceding string from the socket

        @rtype : str

        The Paramiko timeout, as distinct from the socket timeout, is set to the value of the instance's
        self.command_timeout, which is a property

        The channel is then checked for contents. If there is no content before the command_timeout expires, then
        Paramiko will raise a socket.timeout. This will be logged and re-raised to be caught by a higher level
        handler.

        Content received on the channel is checked for the specified pattern match. If found, the content is returned.

        If not found, the channel will be rechecked periodically for the duration of the command_timeout

        If still not found, or if the remote side closed the channel, one of the following exceptions may be raised
        socket.timeout
        nxos_XML_errors.TimeoutExpiredError
        nxos_XML_errors.ServerClosedChannelError

        """

        if isinstance(reguexp, bytes):
            reguexp = reguexp.decode()
        buff = ''
        self.logger.debug("rpexpect first block: Timeout is configured as {0}".format(str(self.command_timeout)))
        socket_timeout = socket.getdefaulttimeout()
        self._channel.settimeout(self.command_timeout)
        paramiko_timeout = self._channel.gettimeout()
        self.logger.debug(
            "rpexpect first block: Socket timeout is {0}, {1}".format(str(socket_timeout), str(paramiko_timeout)))
        looptimer = self.command_timeout
        try:
            self.logger.debug("rpexpect first block: Checking buffer for {}".format(reguexp))
            buff = self._channel.recv(9999)
            self.logger.debug(
                "rpexpect first block: First buff check in thread {0}, {1}".format(
                    str(threading.currentThread().getName()), str(buff)))
        except socket.timeout:
            self.logger.debug(
                "rpexpect first block: First Timeout waiting for intial response.  Received response:  {0}".format(
                    str(buff)))
            raise

        if int(code) == 0:
            return buff[len(buff) - int(characters):]
        elif int(code) == 1:
            return buff[:int(characters) + 1]
        elif int(code) == 2:
            if re.search(reguexp, buff.decode()):
                return True
            else:
                return False
        elif int(code) == 3:
            if re.search(reguexp, buff.decode()):
                return buff
            else:
                return False
        elif int(code) == 4:
            start = time.time()
            self.logger.debug("rpexpect type 4 block: Beginning Loop. Buffer so far {}".format(buff))
            while not re.search(reguexp, buff.decode()):
                #self.logger.debug("Code 4: Inside while loop in rpexpect in thread ")
                try:
                    resp = self._channel.recv(9999)
                except socket.timeout:
                    self.logger.error(
                        "rpexpect type 4 block: Timedout waiting for intial response.  Received response:  {0}".format(
                            buff))
                    raise socket.timeout(
                        "Socket Timedout waiting for expected response {}.  Received response:  {0}".format(reguexp, buff))
                buff += resp
                #self.logger.debug("Second buff check in thread {0}".format(buff))
                stend = time.time()
                if stend - start < 5:
                    pass
                elif stend - start < looptimer:
                    time.sleep(1)
                    pass
                else:
                    self.logger.error(
                        "rpexpect first type 4 block: Loop Timedout after {} seconds.".format(str(stend - start)))
                    self.logger.debug(
                        "rpexpect type 4 block: Loop Timedout waiting for expected response {}. Received response {}".format(
                            reguexp, buff))
                    raise TimeoutExpiredError(
                        "Loop Timedout waiting for expected response {}. Received response {}".format(reguexp, buff))
                if self._channel.exit_status_ready():
                    self.logger.error(
                        "rpexpect type 4 block: Detected server closed channel while waiting for expected response {}. Received response {0:s}".format(
                            reguexp, buff))
                    self.close()
                    raise ServerClosedChannelError(
                        "Detected server closed channel while waiting for expected response. Received response {}".format(
                            reguexp, buff))

        elif int(code) == 5:
            self.logger.debug("rpexpect type 5 block: Starting Type 5 Processing. Beginning Loop. ")
            start = time.time()
            stend = time.time()
            while stend - start < looptimer:
                time.sleep(1)
                #self.logger.debug("Code 5: Inside while loop in rpexpect in thread ")
                try:
                    resp = self._channel.recv(9999)
                except socket.timeout:
                    self.logger.error(
                        "rpexpect type 5 block: Timedout waiting for intial response.  Received response:  {0}".format(
                            buff))
                    raise TimeoutExpiredError(
                        "Socket Timedout waiting for expected response.  Received response:  {0}".format(buff))
                buff += resp
                if self._channel.exit_status_ready():
                    self.logger.error(
                        "rpexpect type 5 block: Detected server closed channel while waiting for expected response. Received response {0:s}".format(
                            buff))
                    self.close()
                    raise ServerClosedChannelError(
                        "Detected server closed channel while waiting for expected response. Received response {}".format(
                            buff))

                    #print buff

        self.logger.debug("rpexpect final block: Returning {}".format(buff))
        #return byte array for xml parser
        return buff

    @checkconnection
    def send(self, message):
        """
        Method for sending message to host
        @type message: str, to be sent to host

        Checks if channel is still open before trying to send.
        """

        self.logger.info("ssh: sending " + message + " to " + self.host)
        try:
            self._channel.send(message)
        except:
            exc_type, exc_value, exc_traceback = sys.exc_info()
            stacktrace = traceback.extract_tb(exc_traceback)
            self.logger.error("Failure sending message " + message + " to " + self.host)
            self.logger.debug(sys.exc_info())
            self.logger.debug(stacktrace)

    def close(self):
        """

        Method to close SSH connection to server


        """
        self.logger.debug("SSH: Close ssh session for {}".format(self.host))
        if self._transport is None:
            return
        if self._transport.is_active():
            self._transport.close()
        self._sshconnected = False

    @property
    def sshconnected(self):
        """
        Checks connection status and returns state of the connection when the self.sshconnected attribute is accessed

        @return: Boolean, Status of current connection
        """
        if self._transport is not None:
            self.logger.debug("Prior connection check status:")
            self.logger.debug("sshconnected {} ".format(self._sshconnected))
            self.logger.debug("transport is active {} ".format(self._transport.is_active()))
            self.logger.debug("transport is authenticated {} ".format(self._transport.is_authenticated()))
            self.logger.debug("exit status ready {} ".format(self._channel.exit_status_ready()))
            _sshconnected = self._transport.is_active() and self._transport.is_authenticated() and not self._channel.exit_status_ready()
            if self._sshconnected and not _sshconnected:
                self.close()
            self._sshconnected = _sshconnected
            self.logger.debug("Post connection check status:")
            self.logger.debug("sshconnected {} ".format(self._sshconnected))
            self.logger.debug("transport is active {} ".format(self._transport.is_active()))
            self.logger.debug("transport is authenticated {} ".format(self._transport.is_authenticated()))
            self.logger.debug("exit status ready {} ".format(self._channel.exit_status_ready()))
        return self._sshconnected


    @property
    def command_timeout(self):
        """
        returns the configured command timeout

        @return: command_timeout
        """
        return self._command_timeout

    @command_timeout.setter
    def command_timeout(self, command_timeout):
        """

        Method to change command_timeout

        @param command_timeout: float
        """
        assert isinstance(command_timeout, float) or isinstance(command_timeout, int)
        self._command_timeout = command_timeout
