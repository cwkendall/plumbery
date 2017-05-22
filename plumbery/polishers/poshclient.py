

from libcloud.compute.ssh import BaseSSHClient

from threading import Thread

from plumbery.polishers.psexec import PSEXEC
from plumbery.plogging import plogging

# this works for python 2.x only
from StringIO import StringIO
import io
from time import sleep
import os
import string
import cmd

class PSExecWrapper(Thread):
    def __init__(self, psexec, rpctransport):
        Thread.__init__(self)
        self._psexec = psexec
        self._rpctransport = rpctransport
 
    def run(self):
        self.stdout = StringIO()
        self.stderr = StringIO()
        r,w = os.pipe()
        self.stdin = io.open(w, "wt", 1000, "utf-8", "strict", '\r\n', True)
        stdin_reader = io.open(r, "rt", 1000, "utf-8", "strict", '\r\n', True)
        self._psexec.doStuff(self._rpctransport, stdin_reader, self.stdout, self.stderr)

    def get_client(self):
        if not self.is_alive:
            return None
        plogging.warning("PSEXEC get client")
        sleep(2)
        client = self._psexec.get_client()
        return client

    def get_share(self):
        plogging.warning("PSEXEC get share")
        return self._psexec.get_share()

    def run_cmd(self, s):
        if self._rpctransport is None:
            return False
        # check stdin is availble
        if self.stdin.closed:
            return False
        plogging.warning("PSEXEC running: "+s)
        #self.stdin.write(unicode(s+'\n'))
        #status =1
        self.stdin.flush()
        if s.split(' ')[0].endswith('.ps1'):
            s = "powershell " + s
        status = self._psexec.get_shell().onecmd(unicode(s + '\r\n'))
        self.stdin.flush()
        sleep(2)
        plogging.warning("PSEXEC out:\n"+self.stdout.getvalue()+" \n\nerr:\n"+self.stderr.getvalue())
        return [self.stdout, self.stderr, status]

    def close():
        self.stdin.flush()
        self.stdin.close()

class POSHClient2(BaseSSHClient):
    def __init__(self, hostname, port=445, username='Administrator', password=None, key_files=None, timeout=None):
       pass
    def connect(self):
       pass
    def put(self, path, contents=None, chmod=None, mode='w'):
       pass
    def run(self, cmd):
       pass 
    def close(self):
       pass


class POSHClient(BaseSSHClient):
    """
    A PowerShell Client powered by Impacket.
    """
    def __init__(self, hostname, port=445, username='Administrator', password=None, key_files=None, timeout=None):
        super(POSHClient, self).__init__(hostname, port, username, password, key_files, timeout)
        self._psexec = PSEXEC(command='cmd.exe', path='C:/Windows/', exeFile=None, copyFile=None, protocols=None, username=username, password=password, domain='', hashes=None,
                      aesKey=None, doKerberos=False, kdcHost=None)
        self._hostname = hostname
        self._port = port
        self._timeout = timeout
        self.ps = None
        #todo allow kerberos key to be used


    def connect(self):
        plogging.warning("POSH Connecting to %s" % (self._hostname))
        for protocol in self._psexec.get_protocols():
            protodef = PSEXEC.KNOWN_PROTOCOLS[protocol]
            port = protodef[1]
            if port == self._port:
                plogging.warning("PSEXEC Connecting to %s (%s)" % (self._hostname, protocol))
                _rpctransport = self._psexec.do_connect(self._hostname, protocol, self._timeout)
                if _rpctransport is None:
                    raise Exception("RPC connection failed")
                self.ps = PSExecWrapper(self._psexec, _rpctransport)
                plogging.warning("POSH launching thread to %s" % (self._hostname))
                self.ps.start()
                return True
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
        return False

    def put(self, path, contents=None, chmod=None, mode='w'):
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

        #todo support mode 'a'='append' using transferClient.writeFile
        client = self.ps.get_client()
        share = self.ps.get_share()

        fh = StringIO(contents)
        f = path
        dst_path = os.path.dirname(f)
        src_file = os.path.basename(f)
        pathname = string.replace(f,'/','\\')

        plogging.info("Uploading %s to %s\%s" % (src_file, share, dst_path))
        client.putFile(share, pathname, fh.read)
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
        client = self.ps.get_client()
        share = self.ps.get_share()

        f = path
        pathname = string.replace(f,'/','\\')
        plogging.info("Deleting file  %s\%s" % (share, pathname))
        return client.deleteFile(share, pathname)

    def run(self, cmd):
        # blocks while command completes
        plogging.info("Running command:  %s" % (cmd))
        return self.ps.run_cmd(cmd)

    def close(self):
        self.run("exit")
        self.ps.close()
        self.ps.join()

if __name__ == '__main__':
    print ("hello from poshclient")

