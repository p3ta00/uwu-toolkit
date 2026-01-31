"""Impacket Ticketer - Create golden/silver Kerberos tickets"""

from modules.auxiliary.impacket._impacket_base import ImpacketModule as _ImpacketModule


class Ticketer(_ImpacketModule):
    def __init__(self):
        super().__init__("ticketer")
        self.name = "impacket_ticketer"
        self.description = "Create golden/silver Kerberos tickets"
