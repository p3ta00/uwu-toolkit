"""Impacket Exchanger - Exchange Web Services (EWS) interaction"""

from modules.auxiliary.impacket._impacket_base import ImpacketModule as _ImpacketModule


class Exchanger(_ImpacketModule):
    def __init__(self):
        super().__init__("exchanger")
        self.name = "impacket_exchanger"
        self.description = "Exchange Web Services (EWS) interaction"
