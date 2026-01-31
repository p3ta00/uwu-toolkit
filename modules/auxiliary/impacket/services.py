"""Impacket Services - Manage Windows services remotely (start/stop/create/delete)"""

from modules.auxiliary.impacket._impacket_base import ImpacketModule as _ImpacketModule


class Services(_ImpacketModule):
    def __init__(self):
        super().__init__("services")
        self.name = "impacket_services"
        self.description = "Manage Windows services remotely (start/stop/create/delete)"
