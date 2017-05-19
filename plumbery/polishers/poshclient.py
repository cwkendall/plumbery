

from libcloud.compute.ssh import BaseSSHClient
from impacket.examples.smbclient

from plumbery.polishers.psexec import PSEXEC
from plumbery.plogging import plogging

# this works for python 2.x only
from StringIO import StringIO

class PSExecWrapper(Thread):
    def __init__(self, hostname, port, username, password, key, timeout):
        Thread.__init__(self)
        self._rpctransport = None
        self._hostname = hostname
        self._timeout = timeout
        self._psexec = PSEXEC(command='cmd.exe', path=None, fileName=None, c=None, None, username, password, domain='', hashes=None,
                      aesKey=None, k=False, dc_ip=None)

    def connect(self):
        for protocol in self._psexec.__protocols:
            self._rpctransport = self._psexec.do_connect(addr, protocol, 100000)
        if self._rpctransport is None:
            return False

    def run(self):
        self._psexec.doStuff(self._rpctransport)

    def get_shell(self):
        if not self.is_alive
            return None
        if self._psexec.shell.transferClient is None:
            self._psexec.shell.connect_transferClient()
        return self._psexec.shell

    def run_cmd(self, s, stdout=None, stderr=None):
        if self._rpctransport is None:
            return False
        # check stdin is availble
        if not self._psexec.shell.stdin.opened
            return Flase
        if stdout is not None:
            self._psexec.stdout_pipe.stdout = stdout
        if stderr is not None:
            self._psexec.stderr_pipe.stderr = stderr
        return cmd.Cmd.onecmd(self._psexec.shell, s)


class POSHClient(BaseSSHClient):
    """
    A PowerShell Client powered by Impacket.
    """
    def __init__(self, hostname, port=439, username='Administrator', password=None, key=None, timeout=None):
        super(POSHClient, self).__init__(hostname, port, username, password, key, timeout)
        self.ps = PSExecWrapper(hostname, port, username, password, key, timeout)


    def connect(self):
        try:
            self.ps.connect() #blocks
            self.ps.start()
        except:
            return False
        #self.client = SMBConnection(self.hostname, self.hostname)
        #lmhash = ''
        #nthash = ''
        #domain = ''
        ##if options.k is True:
        ##    smbClient.kerberosLogin(self.username, self.password, self.domain, self.lmhash, self.nthash, self.options.aesKey, self.options.dc_ip )
        ##else:
        #self.client.login(username, password, domain, lmhash, nthash)
        #
        #conninfo = {'hostname': self.hostname,
        #            'port': self.port,
        #            'username': self.username,
        #            'password': self.password,
        #            'allow_agent': False,
        #            'look_for_keys': False}
        #self.client.connect(**conninfo)
        return True

    def put(self, path, contents=None, chmod=None):
        """
        Upload a file to the remote node.
        :type path: ``str``
        :keyword path: File path on the remote node.
        :type contents: ``str``
        :keyword contents: File Contents.
        :type chmod: ``int``
        :keyword chmod: chmod file to this after creation.
        :type mode: ``str``
        :keyword mode: Mode in which the file is opened.
        :return: Full path to the location where a file has been saved.
        :rtype: ``str``
        """
        shell = self.ps.get_shell()

        fh = StringIO(contents)
        f = path
        dst_path = os.path.dirname(f)
        src_file = os.path.basename(f)
        pathname = string.replace(f,'/','\\')

        plogging.info("Uploading %s to %s\%s" % (src_file, shell.share, dst_path))
        shell.transferClient.putFile(shell.share, pathname.decode(shell.stdin.encoding), fh.read)
        fh.close()
        return pathname

    def delete(self, path):
        """
        Delete/Unlink a file on the remote node.
        :type path: ``str``
        :keyword path: File path on the remote node.
        :return: True if the file has been successfully deleted, False
                 otherwise.
        :rtype: ``bool``
        """
        shell = self.ps.get_shell()

        f = path
        pathname = string.replace(f,'/','\\')
        plogging.info("Deleting file  %s\%s" % (shell.share, pathname))
        return shell.transferClient.deleteFile(shell.share, pathname)

    def run(self, cmd):
        shell = self.ps.get_shell()
        stdout = StringIO()
        stderr = StringIO()
        # blocks while command completes
        plogging.info("Running command:  %s" % (cmd))

        status = shell.run_cmd(cmd, stdout, stderr)
        return [stdout, stderr, status]

    def close(self):
        self.run("exit")
        self.ps.join()
