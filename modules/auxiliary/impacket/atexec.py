"""Impacket ATExec - Exec via Task Scheduler (creates scheduled task)"""

from modules.auxiliary.impacket._impacket_base import ImpacketModule as _ImpacketModule


class ATExec(_ImpacketModule):
    def __init__(self):
        super().__init__("atexec")
        self.name = "impacket_atexec"
        self.description = "Exec via Task Scheduler (creates scheduled task)"
