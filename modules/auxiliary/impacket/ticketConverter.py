"""Impacket TicketConverter - Convert tickets between ccache and kirbi formats"""

from modules.auxiliary.impacket._impacket_base import ImpacketModule as _ImpacketModule


class TicketConverter(_ImpacketModule):
    def __init__(self):
        super().__init__("ticketConverter")
        self.name = "impacket_ticketConverter"
        self.description = "Convert tickets between ccache and kirbi formats"
