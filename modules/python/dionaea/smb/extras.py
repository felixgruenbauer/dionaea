from . import rpcservices
#from .smb import smblog
import fs.memoryfs
import os
from .include.smbfields import SMB_SERVICE_DISK_SHARE,SMB_SERVICE_NAMED_PIPE,SMB_SERVICE_PRINT_SHARE
import logging 

smblog = logging.getLogger('SMB')


class SmbConfig(object):
    """
    This class helps to access the config values.
    """

    def __init__(self, config=None):
        """
        :param config: The config dict from dionaea
        :type config: Dict

        """
        if config is None:
            config = {}

        #self.native_os = "Windows 5.1"
        self.native_os = "Windows Server 2003 R2 3790 Service Pack 2"
        #self.native_os = "Windows 7 Professional N 7601 Service Pack 1"
        #self.native_lan_manager = "Windows 2000 LAN Manager"
        self.native_lan_manager = "Windows Server 2003 R2 5.2"
        #self.native_lan_manager = "Windows 7 Professional N 6.1"
        self.oem_domain_name = "WORKGROUP"
        self.os_type = 2
        self.primary_domain = "WORKGROUP"
        self.server_name = "HOMEUSER-3AF6FE"
        self.shares = {}
        self.memfs_limit = 60000000
        self.active_con_limit = 4

        default_shares = {
            "ADMIN$" : {
                "comment" : "Remote Admin",
                "path": "C:\\Windows",
                "type": "disktree"
            },
            "C$" : {
                "comment" : "Default Share",
                "path": "C:\\",
                "type": ["disktree", "special"]
            },
            "IPC$" : {
                "comment" : "Remote IPC",
                "path": "",
                "type": "ipc",
                "nativefs": ""
            },
            "Printer" : {
                "comment" : "Microsoft XPS Document Writer",
                "path": "",
                "type": "printq",
            },
       }


        value_names = [
            "native_lan_manager",
            "native_os",
            "oem_domain_name",
            "os_type",
            "primary_domain",
            "server_name",
            "memfs_limit",
            "active_con_limit",
        ]
        for name in value_names:
            value = config.get(name)
            if value is None:
                continue
            smblog.debug("Set '%s' to '%s'" % (name, value))
            setattr(self, name, value)

        shares = config.get("shares")
        if shares is None:
            shares = default_shares
        for name, options in shares.items():
            cfg_share_types = options["type"]
            if not isinstance(cfg_share_types, list):
                cfg_share_types = [cfg_share_types]
            share_type = 0x00000000
            share_service = SMB_SERVICE_DISK_SHARE
            for cfg_share_type in cfg_share_types:
                if cfg_share_type.lower() == "disktree":
                    share_type |= rpcservices.STYPE_DISKTREE
                    share_service = SMB_SERVICE_DISK_SHARE
                elif cfg_share_type.lower() == "ipc":
                    share_type |= rpcservices.STYPE_IPC
                    share_service = SMB_SERVICE_NAMED_PIPE
                elif cfg_share_type.lower() == "printq":
                    share_type |= rpcservices.STYPE_PRINTQ
                    share_service = SMB_SERVICE_PRINT_SHARE
                elif cfg_share_type.lower() == "special":
                    share_type |= rpcservices.STYPE_SPECIAL

            self.shares[name] = {
                "name": name,
                "comment": options.get("comment", ""),
                "path": options.get("path", ""),
                "type": share_type,
                "service": share_service,
                "memfs": None,
                "nativefs": options.get("nativefs", ""),
                "local_path": options.get("local_path", None)
            }


        self.time_margin = config.get("time_margin", 10)
        self.entropy_threshold = config.get("entropy_threshold", 0.3)
        self.score_threshold = config.get("score_threshold", 200)


    def load_local_dir(self, path):
        memfs = fs.memoryfs.MemoryFS()
        try:
            os.chdir(path)
        except FileNotFoundError:
            smblog.error("local_path not found, using default MemoryFS instead")
            return self.create_def_fs()

        for root, dirs, files in os.walk("."):
            memfs.makedirs(root, recreate=True)
            for f in files:
                file_name = fs.path.join(root, f)
                with open(file_name, "rb") as content_file:
                    memfs.setbytes(file_name, content_file.read())
        return memfs

        
    def create_def_fs(self):
        memfs = fs.memoryfs.MemoryFS()
        memfs.makedirs("/Users/pete")
        memfs.makedirs("/pictures/vacation")
        memfs.setbytes("/Users/pete/attachement.txt", b"test")
        memfs.setbytes("/Users/pete/password.txt", b"pete"*16)
        memfs.setbytes("/Hello.txt", b"pete"*16)
        return memfs 

    def get_share_fs(self, share_name):
        if self.shares[share_name]["local_path"]:
            return self.load_local_dir(self.shares[share_name]["local_path"])
        else:
            return self.create_def_fs()
