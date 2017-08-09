import abc
from .include.smbfields import *
import datetime
from dionaea.core import incident
import fs.memoryfs
import magic
import math
import scipy.stats
import numpy as np

FILE_OP_READ        = 0
FILE_OP_WRITE       = 1
FILE_OP_OVERWRITE   = 2
FILE_OP_OPEN        = 3
FILE_OP_CLOSE       = 4
FILE_OP_CREATE      = 5
FILE_OP_DELETE      = 6
FILE_OP_RENAME      = 7
FILE_OP_TRUNC       = 8

File_Ops = {
    FILE_OP_READ        : "Read File",
    FILE_OP_WRITE       : "Write File",
    FILE_OP_OVERWRITE   : "Overwrite File",
    FILE_OP_OPEN        : "Open File",
    FILE_OP_CLOSE       : "Close File",
    FILE_OP_CREATE      : "Create File",
    FILE_OP_DELETE      : "Delete File",
    FILE_OP_RENAME      : "Rename File",
    FILE_OP_TRUNC       : "Truncate File",
}


class RansomwareDetection():
    def __init__(self, shares):
        self.config = "" 
        self.shares = shares
        self.malice_score = 0
        self.results = {}
        self.ops = {} 
        for k in shares:
            self.ops[k] = {}

        self.indicators = []
        self.classificators = []

        self.indicators.append(OpsPerFileExt())
        self.indicators.append(AccessPatternClasses(self.ops, shares))
        self.indicators.append(EncryptionIndic(self.ops, shares))
        self.indicators.append(EntropyIndic(self.ops, shares))
        self.indicators.append(FileMagicIndic(self.ops, shares))

    def apply_config(self, config):
        self.config = config


    def new_file_op(self, op, file_name, share, new_file_name=None):
        timestamp = datetime.datetime.now()
        if not file_name in self.ops[share]:
            self.ops[share][file_name] = {
                "ops": {}, 
                "orig": None, 
                "modified": None, 
                "rwd": {},
                }
        self.ops[share][file_name]["ops"][op] = timestamp 

        print(File_Ops[op], file_name, new_file_name, timestamp)
        # save orig file
        if op in [FILE_OP_DELETE, FILE_OP_TRUNC, FILE_OP_OPEN]:
            self.ops[share][file_name]["orig"] = self.shares[share]["FS"].getbytes(file_name)


        # save modified file
        if op == FILE_OP_CLOSE and (FILE_OP_WRITE in self.ops[share][file_name]["ops"] or FILE_OP_OVERWRITE in self.ops[share][file_name]["ops"]):
            self.ops[share][file_name]["modified"] = self.shares[share]["FS"].getbytes(file_name)

        if op == FILE_OP_RENAME:
            if file_name in self.ops[share]:
                self.ops[share][new_file_name] = self.ops[share].pop(file_name)
                file_name = new_file_name


        #if op == FILE_OP_CLOSE and (FILE_OP_WRITE in self.ops[share][file_name]["ops"] or FILE_OP_OVERWRITE in self.ops[share][file_name]["ops"]):
        for i in self.indicators:
            self.malice_score += i.check_for_rw(file_name, op, timestamp, self.ops[share]) 

        print("malice score:", self.malice_score) 
        print(self.ops[share][file_name]["rwd"])


    def handle_disc(self):
            i = incident("dionaea.modules.python.smb.rwd.disc")
            i.con = self
            i.malice_score = self.malice_score 
            details = {} 
            for share in self.ops.keys():
                details[share] = {}
                for f in self.ops[share]:
                    if "rwd" in self.ops[share][f]:
                        details[share][f] = self.ops[share][f]["rwd"]

            #i.details = details 
            print(details)
            i.report()





class AbstractIndicator(abc.ABC):

    def required_ops(self):
        """ should return the file ops the indicator wants to be informed about """
        return list(range(9))

    @abc.abstractmethod
    def check_for_rw(self, file_name, op, timestamp, share_ops):
        pass



class AccessPatternClasses(AbstractIndicator): 
    def __init__(self, ops, shares):
        self.rw_classes = dict.fromkeys(["A", "B", "C"], 0)

    def required_ops(self):
        ops = []
        ops.append(FILE_OP_DELETE)
        ops.append(FILE_OP_OVERWRITE)
        ops.append(FILE_OP_CLOSE)
        return ops


    def check_for_rw(self, file_name, op, timestamp, share_ops):
        file_ops = share_ops[file_name]["ops"]

        # class A : in papers: open -> read -> overwrite -> close
        # smb: open > read > (close > trunc > write)/overwrite > close
        if op == FILE_OP_CLOSE:
            if set([FILE_OP_OVERWRITE, FILE_OP_READ, FILE_OP_OPEN]).issubset(file_ops):
                if file_ops[FILE_OP_OVERWRITE] > file_ops[FILE_OP_READ]:
                    self.rw_classes["A"] += 1 
                    share_ops[file_name]["rwd"]["access_pattern"] = ("A", file_name, file_name)
                    #share_ops[file_name]["enc_file"] = file_name
                    return 1 
            elif set([FILE_OP_WRITE, FILE_OP_TRUNC, FILE_OP_READ, FILE_OP_OPEN]).issubset(file_ops):
                if file_ops[FILE_OP_WRITE] > file_ops[FILE_OP_TRUNC] > file_ops[FILE_OP_READ]:
                    self.rw_classes["A"] += 1 
                    share_ops[file_name]["rwd"]["access_pattern"] = ("A", file_name, file_name)
                    #share_ops[file_name]["enc_file"] = file_name
                    return 1 

        # class B: file x open->read->close->delete/trunc
        #           file x.locked -> create->write-> close
        # smb: file x open > read > [overwrite] > close > (trunc/delete)
        #   file x.locked create > write > close
        # find encrypted file throuhgh filename or creationtime
        search_pattern = file_name.split("/")[-1]
        search_pattern = fs.path.splitext(search_pattern)[0]
        margin = datetime.timedelta(seconds=30)

        if op == FILE_OP_CLOSE and set([FILE_OP_WRITE, FILE_OP_CREATE]).issubset(file_ops):

            # look for locked file 
            by_name = []  
            by_time = []
            for f in share_ops: 
                if FILE_OP_READ in share_ops[f]["ops"] and (
                        FILE_OP_DELETE in share_ops[f]["ops"] or FILE_OP_TRUNC in share_ops[f]["ops"]):
                    if f.find(search_pattern) != -1:
                        by_name.append(f)
                    if share_ops[f]["ops"][FILE_OP_READ] < file_ops[FILE_OP_WRITE] < share_ops[f]["ops"][FILE_OP_READ] + margin:
                        by_time.append(f)
            locked_files = set(by_name).intersection(by_time)
            try:
                locked_files.remove(file_name)
            except KeyError:
                pass
            if not locked_files:
                locked_files = by_time

            locked_file = None 
            if len(locked_files) > 1:
                locked_file = min(locked_files, key=lambda x: abs(file_ops[FILE_OP_WRITE] - share_ops[x]["ops"][FILE_OP_READ]))
            elif len(locked_files) == 1:
                locked_file = by_time[0]

            if locked_file:
                share_ops[file_name]["rwd"]["access_pattern"] = ("B", locked_file, file_name)
                share_ops[locked_file]["rwd"]["access_pattern"] = ("B", locked_file, file_name)
                self.rw_classes["B"] += 1
                return 1


        if op in [FILE_OP_DELETE, FILE_OP_TRUNC, FILE_OP_OVERWRITE] and FILE_OP_READ in file_ops: 
                
            # look for locked file 
            by_name = []  
            by_time = []
            for f in share_ops: 
                if set([FILE_OP_WRITE, FILE_OP_CREATE]).issubset(share_ops[f]["ops"]):
                    if f.find(search_pattern) != -1:
                        by_name.append(f)
                    if file_ops[FILE_OP_READ] < share_ops[f]["ops"][FILE_OP_WRITE] < file_ops[FILE_OP_READ] + margin:
                        by_time.append(f)
            locked_files = list(set(by_name).intersection(by_time))
            try:
                locked_files.remove(file_name)
            except ValueError:
                pass
            if not locked_files:
                locked_files = by_time

            locked_file = None 
            if len(locked_files) > 1:
                locked_file = min(locked_files, key=lambda x: abs(share_ops[x]["ops"][FILE_OP_WRITE] - file_ops[FILE_OP_READ]))
            elif len(locked_files) == 1:
                locked_file = by_time[0]

            if locked_file:
                #share_ops[file_name]["modified"] = share_ops[locked_file]["modified"]
                self.rw_classes["B"] += 1
                share_ops[file_name]["rwd"]["access_pattern"] = ("B", file_name, locked_file)
                share_ops[locked_file]["rwd"]["access_pattern"] = ("B", file_name, locked_file)
                return 1

        return 0


class EntropyIndic(AbstractIndicator):
    def __init__(self, config, ops):
        self.config = config
        self.ops = ops
        self.ent_thres = 0.3

    def required_ops(self):
        return [FILE_OP_DELETE, FILE_OP_CLOSE]

    def entropy(self, data):
        #orig_count = np.bincount(np.fromstring(orig_file, np.ubyte))
        counts = np.bincount(data)
        counts = np.trim_zeros(np.sort(counts))
        sz = sum(counts)
        p = counts / sz
        ent = -sum(p * np.log(p) / math.log(256))
        return ent * 8

    def check_for_rw(self, file_name, op, timestamp, share_ops):
        file_info = share_ops[file_name]
        if not (op == FILE_OP_DELETE or (op == FILE_OP_CLOSE and (FILE_OP_WRITE in file_info["ops"] or FILE_OP_OVERWRITE in file_info["ops"]))):
            return 0
        if not "access_pattern" in file_info["rwd"]:
            return 0
        orig = share_ops[file_info["rwd"]["access_pattern"][1]]["orig"]
        mod = share_ops[file_info["rwd"]["access_pattern"][2]]["modified"]
        orig_ent = self.entropy(np.fromstring(orig, np.ubyte)) 
        mod_ent = self.entropy(np.fromstring(mod, np.ubyte)) 
        diff = math.fabs(orig_ent - mod_ent)
        if diff > self.ent_thres:
            share_ops[file_name]["rwd"]["entropy"] = (diff) 
            return 1
        return 0

class FileMagicIndic(AbstractIndicator):
    def __init__(self, config, ops):
        self.config = config
        self.ops = ops

    def check_for_rw(self, file_name, op, timestamp, share_ops):
        result = 0
        file_info = share_ops[file_name]
        if not (op == FILE_OP_DELETE or (op == FILE_OP_CLOSE and (FILE_OP_WRITE in file_info["ops"] or FILE_OP_OVERWRITE in file_info["ops"]))):
            return 0
        if not "access_pattern" in file_info["rwd"]:
            return 0
        orig = share_ops[file_info["rwd"]["access_pattern"][1]]["orig"]
        mod = share_ops[file_info["rwd"]["access_pattern"][2]]["modified"]

        orig_magic = magic.from_buffer(orig)
        mod_magic = magic.from_buffer(mod)
        result = mod_magic != orig_magic
        if result:
            share_ops[file_name]["rwd"]["file_magic"] = (orig_magic, mod_magic)
        return result



class EncryptionIndic(AbstractIndicator):
    def __init__(self, config, ops):
        self.config = config
        self.ops = ops

    def required_ops(self):
        return [FILE_OP_DELETE, FILE_OP_CLOSE]

    def mc_pi(self, data):
        #monte = np.fromstring(locked_file, dtype=np.ubyte)
        #locked_file = locked_file[:len(locked_file) // 8 * 8]
        #xy = np.fromstring(locked_file, dtype=np.float32)
        ##xy = np.fromstring(locked_file, dtype=np.uint32)
        #x = xy[0::2]
        #y = xy[1::2]
        #r = x*x + y*y
        #mcpi = 4 * np.count_nonzero(r < 1) / len(x)
    
        MONTEN = 6
        incirc = (256.0**(MONTEN // 2) - 1)**2
        d = np.array(data, copy=True, dtype=np.float64)
        d = d[:len(d) // MONTEN * MONTEN]
        values = np.sum(
            d.reshape((-1, MONTEN // 2)) * np.array([256**2, 256, 1]), axis=1)
        montex = values[0::2]
        montey = values[1::2]
        dist2 = montex * montex + montey * montey
        inmont = np.count_nonzero(dist2 <= incirc)
        return 4 * inmont / len(montex)

    def check_for_rw(self, file_name, op, timestamp, share_ops):
        if not (op == FILE_OP_CLOSE and (FILE_OP_WRITE in share_ops[file_name]["ops"] or FILE_OP_OVERWRITE in share_ops[file_name]["ops"])):
            return 0
        if not share_ops[file_name]["modified"]:
            return 0

        file_content = share_ops[file_name]["modified"]
        file_content = np.fromstring(file_content, dtype=np.ubyte)
        if not len(file_content) // 6 * 6:
            return 0
        chi = scipy.stats.chisquare(np.bincount(file_content)).statistic
        mcpi = self.mc_pi(file_content)
        mcpi = 100 * (math.fabs(math.pi - mcpi)/math.pi)

        if chi > 1500:
            return 0
        if mcpi > 1.5:
            return 0
        if mcpi > 0.5 and chi > 500:
            return 0
        share_ops[file_name]["rwd"]["enc_indic"] = (mcpi, chi)
        return 1 


class OpsPerFileExt(AbstractIndicator):
    def __init__(self):
        self.ops_per_ext = {}

    def check_for_rw(self, file_name, op, timestamp, share_ops):
        file_name = file_name.split("/")[-1]
        ext = ""
        if file_name.find(".") != -1:
            ext = file_name.split(".")[-1]
        if not ext in self.ops_per_ext:
            self.ops_per_ext[ext] = dict.fromkeys(range(9), 0) 
        self.ops_per_ext[ext][op] += 1
        return 0


