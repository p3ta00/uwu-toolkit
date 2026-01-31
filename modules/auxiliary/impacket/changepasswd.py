"""Impacket ChangePasswd - Change user password via multiple protocols"""

from modules.auxiliary.impacket._impacket_base import ImpacketModule as _ImpacketModule


class ChangePasswd(_ImpacketModule):
    def __init__(self):
        super().__init__("changepasswd")
        self.name = "impacket_changepasswd"
        self.description = "Change user password via multiple protocols"
