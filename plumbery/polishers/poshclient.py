

from libcloud.compute.ssh import BaseSSHClient
from impacket.examples.smbclient

class POSHClient(BaseSSHClient):
    """
    A PowerShell Client powered by Impacket.
    """
    def __init__(self, hostname, port=439, username='Administrator', password=None, key=None):
        super(ParamikoSSHClient, self).__init__(hostname, port, username, password, key)


    def connect(self):
      try:
        self.client = SMBConnection(self.hostname, self.hostname)
        if options.k is True:
            smbClient.kerberosLogin(self.username, self.password, self.domain, self.lmhash, self.nthash, self.options.aesKey, self.options.dc_ip )
        else:
            smbClient.login(username, password, domain, lmhash, nthash)

        conninfo = {'hostname': self.hostname,
                    'port': self.port,
                    'username': self.username,
                    'password': self.password,
                    'allow_agent': False,
                    'look_for_keys': False}
        self.client.connect(**conninfo)

        return True

    def put(self, path, contents=None, chmod=None):


    def delete(self, path):


    def run(self, cmd):


        #
        status = chan.recv_exit_status()
        so = stdout.read()
        se = stderr.read()
        return [so, se, status]

    def close(self):
        self.client.close()
