import abc
from .include.smbfields import *
import datetime
from dionaea.core import incident
import fs.memoryfs
import magic
import math
import scipy.stats
import numpy as np
import logging

rwdlog = logging.getLogger('RWD')


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
    def __init__(self, shares, config, ip):
        self.ip = ip
        self.config = config 
        self.shares = shares
        self.malice_score = 0
        self.results = {}
        self.ops = {} 
        for k in shares:
            self.ops[k] = {}

        self.indicators = []
        self.access_pattern = AccessPattern(self.ops, self.config.time_margin)
        self.indicators.append(OpsPerExt())
        self.indicators.append(Encryption(self.shares, self.ops))
        self.indicators.append(EntropyDiff(self.shares, self.ops, self.config.entropy_threshold))
        self.indicators.append(FileMagic(self.shares, self.ops))

    def new_file_op(self, op, file_name, share_name, new_file_name=None):
        timestamp = datetime.datetime.now()
        if not file_name in self.ops[share_name]:
            self.ops[share_name][file_name] = {
                "ops": {}, 
                "orig": None, 
                "modified": None, 
                "old_names": [],
                "rwd": {},
                }
        self.ops[share_name][file_name]["ops"][op] = timestamp 

        rwdlog.info("New file op: %s %s %s %s"%(File_Ops[op], file_name, new_file_name, timestamp))
        #rwdlog.info(File_Ops[op], file_name, new_file_name, timestamp)
        # save orig file
        if op in [FILE_OP_DELETE, FILE_OP_TRUNC, FILE_OP_OPEN]:
            if not self.ops[share_name][file_name]["orig"]:
                self.ops[share_name][file_name]["orig"] = self.shares[share_name]["memfs"].getbytes(file_name)


        # save modified file
        if op == FILE_OP_CLOSE and (FILE_OP_WRITE in self.ops[share_name][file_name]["ops"] or FILE_OP_OVERWRITE in self.ops[share_name][file_name]["ops"]):
            self.ops[share_name][file_name]["modified"] = self.shares[share_name]["memfs"].getbytes(file_name)

        if op == FILE_OP_RENAME:
            if file_name in self.ops[share_name]:
                self.ops[share_name][new_file_name] = self.ops[share_name].pop(file_name)
                self.ops[share_name][new_file_name]["old_names"].append(file_name)
                file_name = new_file_name



        score, files = self.access_pattern.check(file_name, op, timestamp, share_name)
        self.malice_score += score 
        if files:
            rwdlog.info("malice score: %d(%d) %s %s"%(self.malice_score, score, "AccessPattern", files))
            print("malice score: %d(%d) %s %s"%(self.malice_score, score, "AccessPattern", files))

        for i in self.indicators:
            if files:
                score, result = i.check(file_name, op, timestamp, share_name, files) 
            else:
                score, result = i.check(file_name, op, timestamp, share_name) 
            if result and score:
                self.malice_score += score 
                rwdlog.info("malice_score: %d(%d) %s %s"%(self.malice_score, score, i.__class__.__name__, result))
                print("malice_score: %d(%d) %s %s"%(self.malice_score, score, i.__class__.__name__, result))




    def handle_disc(self):
        self.compile_report()

    def compile_report(self):
        i = incident("dionaea.modules.python.smb.rwd.disc")
        report = {}
        report[self.access_pattern.__class__.__name__] = self.access_pattern.get_results()
        for indic in self.indicators:
            report[indic.__class__.__name__] = indic.get_results()

        print(report)
        i.client_ip = self.ip
        i.malice_score = self.malice_score 
        i.report()




class AbstractIndicator(abc.ABC):

    @abc.abstractmethod
    def check(self, file_name, op, timestamp, share_ops, files=None):
        pass

    @abc.abstractmethod
    def get_results(self):
        pass



class AccessPattern(AbstractIndicator): 
    def __init__(self, ops, time_margin):
        self.results = {
            "A": [],
            "B": [],
        }
        self.ops = ops
        self.time_margin = time_margin

    def get_results(self):
        return self.results

    def check(self, file_name, op, timestamp, share_name, files=None):
        share_ops = self.ops[share_name]
        file_ops = share_ops[file_name]["ops"]

        # class A : in papers: open -> read -> overwrite -> close
        # smb: open > read > (close > trunc > write)/overwrite > close
        if op == FILE_OP_CLOSE:
            if set([FILE_OP_OVERWRITE, FILE_OP_READ, FILE_OP_OPEN]).issubset(file_ops):
                if file_ops[FILE_OP_OVERWRITE] > file_ops[FILE_OP_READ]:
                    result = (file_name, file_name)
                    self.results["A"].append(result) 
                    return 1, result 
            elif set([FILE_OP_WRITE, FILE_OP_TRUNC, FILE_OP_READ, FILE_OP_OPEN]).issubset(file_ops):
                if file_ops[FILE_OP_WRITE] > file_ops[FILE_OP_TRUNC] > file_ops[FILE_OP_READ]:
                    result = (file_name, file_name)
                    self.results["A"].append(result) 
                    return 1, result 

        # class B: file x open->read->close->delete/trunc
        #           file x.locked -> create->write-> close
        # smb: file x open > read > [overwrite] > close > (trunc/delete)
        #   file x.locked create > write > close
        # find encrypted file throuhgh filename or creationtime
        search_pattern = file_name.split("/")[-1]
        search_pattern = fs.path.splitext(search_pattern)[0]
        self.time_margin = datetime.timedelta(seconds=30)

        if op == FILE_OP_CLOSE and set([FILE_OP_WRITE, FILE_OP_CREATE]).issubset(file_ops):

            # look for orig file 
            by_name = []  
            by_time = []
            for f in share_ops: 
                if FILE_OP_READ in share_ops[f]["ops"] and (
                        FILE_OP_DELETE in share_ops[f]["ops"] or FILE_OP_TRUNC in share_ops[f]["ops"]):
                    if f.find(search_pattern) != -1:
                        by_name.append(f)
                    if share_ops[f]["ops"][FILE_OP_READ] < file_ops[FILE_OP_WRITE] < share_ops[f]["ops"][FILE_OP_READ] + self.time_margin:
                        by_time.append(f)
            orig_files = set(by_name).intersection(by_time)
            try:
                orig_files.remove(file_name)
            except KeyError:
                pass
            if not orig_files:
                orig_files = by_time

            orig_file = None 
            if len(orig_files) > 1:
                orig_file = min(orig_files, key=lambda x: abs(file_ops[FILE_OP_WRITE] - share_ops[x]["ops"][FILE_OP_READ]))
            elif len(orig_files) == 1:
                orig_file = by_time[0]

            if orig_file:
                result = (orig_file, file_name)
                self.results["B"].append(result)   
                return 1, result 


        if op in [FILE_OP_DELETE, FILE_OP_TRUNC, FILE_OP_OVERWRITE] and FILE_OP_READ in file_ops: 
                
            # look for locked file 
            by_name = []  
            by_time = []
            for f in share_ops: 
                if set([FILE_OP_WRITE, FILE_OP_CREATE]).issubset(share_ops[f]["ops"]):
                    if f.find(search_pattern) != -1:
                        by_name.append(f)
                    if file_ops[FILE_OP_READ] < share_ops[f]["ops"][FILE_OP_WRITE] < file_ops[FILE_OP_READ] + self.time_margin:
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
                result = (file_name, locked_file) 
                self.results["B"].append(result)   
                return 1, result 

        return 0, None 


class EntropyDiff(AbstractIndicator):
    def __init__(self, shares, ops, ent_thres):
        self.shares = shares
        self.ops = ops
        self.results = {}
        self.ent_thres = ent_thres 

    def required_ops(self):
        return [FILE_OP_DELETE, FILE_OP_CLOSE]

    def get_results(self):
        return self.results

    def entropy(self, data):
        #orig_count = np.bincount(np.fromstring(orig_file, np.ubyte))
        counts = np.bincount(data)
        counts = np.trim_zeros(np.sort(counts))
        sz = sum(counts)
        p = counts / sz
        ent = -sum(p * np.log(p) / math.log(256))
        return ent * 8

    def check(self, file_name, op, timestamp, share_name, files=None):
        share_ops = self.ops[share_name]
        if not files:
            return 0, None
        orig_file, locked_file = files
        if not share_ops[orig_file]["orig"] and not share_ops[locked_file]["modified"]:
            return 0, None
        orig = share_ops[orig_file]["orig"]
        mod = share_ops[locked_file]["modified"]
        orig_ent = self.entropy(np.fromstring(orig, np.ubyte)) 
        mod_ent = self.entropy(np.fromstring(mod, np.ubyte)) 
        diff = math.fabs(orig_ent - mod_ent)
        if diff > self.ent_thres:
            self.results[files] = diff
            return 1, diff
        return 0, diff

class FileMagic(AbstractIndicator):
    def __init__(self, shares, ops):
        self.shares = shares
        self.ops = ops
        self.results = {} 

    def get_results(self):
        return self.results

    def check(self, file_name, op, timestamp, share_name, files=None):
        if not files:
            return 0, None
        share_ops = self.ops[share_name]
        orig_file, locked_file = files
        if not share_ops[orig_file]["orig"] and not share_ops[locked_file]["modified"]:
            return 0, None
        orig_magic = magic.from_buffer(share_ops[orig_file]["orig"])
        mod_magic = magic.from_buffer(share_ops[locked_file]["modified"])
        result = (orig_magic, mod_magic)
        if orig_magic != mod_magic:
            self.results[files] = result
            return 1, result 
        return 0, result



class Encryption(AbstractIndicator):
    def __init__(self, shares, ops):
        self.shares = shares
        self.ops = ops
        self.results = {}

    def get_results(self):
        return self.results

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

    def check(self, file_name, op, timestamp, share_name, files=None):
        file_ops = self.ops[share_name][file_name]
        if not (op == FILE_OP_CLOSE and (FILE_OP_WRITE in file_ops["ops"] or FILE_OP_OVERWRITE in file_ops["ops"])):
            return 0, None
        if not file_ops["modified"]:
            return 0, None

        file_content = file_ops["modified"]
        file_content = np.fromstring(file_content, dtype=np.ubyte)
        if not len(file_content) // 6 * 6:
            return 0, None
        chi = scipy.stats.chisquare(np.bincount(file_content)).statistic
        mcpi = self.mc_pi(file_content)
        mcpi = 100 * (math.fabs(math.pi - mcpi)/math.pi)
        result = (mcpi, chi)


        if (chi > 1500) or (mcpi > 1.5):
            return 0, None
        if mcpi > 0.5 and chi > 500:
            return 0, None
        name = fs.path.join(share_name, file_name)
        self.results[name] = result 
        return 1, result 


class OpsPerExt(AbstractIndicator):
    def __init__(self):
        self.results = {}

    def get_results(self):
        return self.results

    def check(self, file_name, op, timestamp, share_ops, files=None):
        ext = fs.path.splitext(file_name) 
        if not ext in self.results:
            self.results[ext] = dict.fromkeys(range(9), 0) 
        self.results[ext][op] += 1
        return 0, None


