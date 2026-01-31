"""Impacket SMBPasswd - Change SMB password remotely"""

from modules.auxiliary.impacket._impacket_base import ImpacketModule as _ImpacketModule


class SMBPasswd(_ImpacketModule):
    def __init__(self):
        super().__init__("smbpasswd")
        self.name = "impacket_smbpasswd"
        self.description = "Change SMB password remotely"
