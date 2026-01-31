"""Impacket SMBServer - Host files via SMB server (for file transfers)"""

from modules.auxiliary.impacket._impacket_base import ImpacketModule as _ImpacketModule


class SMBServer(_ImpacketModule):
    def __init__(self):
        super().__init__("smbserver")
        self.name = "impacket_smbserver"
        self.description = "Host files via SMB server (for file transfers)"
