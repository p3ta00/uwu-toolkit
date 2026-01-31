"""Impacket SMBClient - SMB client - list shares, upload/download files"""

from modules.auxiliary.impacket._impacket_base import ImpacketModule as _ImpacketModule


class SMBClient(_ImpacketModule):
    def __init__(self):
        super().__init__("smbclient")
        self.name = "impacket_smbclient"
        self.description = "SMB client - list shares, upload/download files"
