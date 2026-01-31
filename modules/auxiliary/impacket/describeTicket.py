"""Impacket DescribeTicket - Parse and describe Kerberos ticket contents"""

from modules.auxiliary.impacket._impacket_base import ImpacketModule as _ImpacketModule


class DescribeTicket(_ImpacketModule):
    def __init__(self):
        super().__init__("describeTicket")
        self.name = "impacket_describeTicket"
        self.description = "Parse and describe Kerberos ticket contents"
