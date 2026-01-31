"""Impacket AddComputer - Add a computer account to the domain"""

from modules.auxiliary.impacket._impacket_base import ImpacketModule as _ImpacketModule


class AddComputer(_ImpacketModule):
    def __init__(self):
        super().__init__("addcomputer")
        self.name = "impacket_addcomputer"
        self.description = "Add a computer account to the domain"
