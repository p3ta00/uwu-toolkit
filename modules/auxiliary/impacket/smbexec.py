"""Impacket SMBExec - Exec via SMB services (no binary upload)"""

from modules.auxiliary.impacket._impacket_base import ImpacketModule as _ImpacketModule


class SMBExec(_ImpacketModule):
    def __init__(self):
        super().__init__("smbexec")
        self.name = "impacket_smbexec"
        self.description = "Exec via SMB services (no binary upload)"
