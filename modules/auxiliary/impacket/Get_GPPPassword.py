"""Impacket GetGPPPassword - Extract Group Policy Preferences passwords"""

from modules.auxiliary.impacket._impacket_base import ImpacketModule as _ImpacketModule


class GetGPPPassword(_ImpacketModule):
    def __init__(self):
        super().__init__("Get-GPPPassword")
        self.name = "impacket_Get-GPPPassword"
        self.description = "Extract Group Policy Preferences passwords"
