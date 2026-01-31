"""Impacket NTFSRead - Read files from NTFS volumes"""

from modules.auxiliary.impacket._impacket_base import ImpacketModule as _ImpacketModule


class NTFSRead(_ImpacketModule):
    def __init__(self):
        super().__init__("ntfs_read")
        self.name = "impacket_ntfs_read"
        self.description = "Read files from NTFS volumes"
