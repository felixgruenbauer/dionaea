#*************************************************************************
#*                               Dionaea
#*                           - catches bugs -
#*
#*
#*
#* Copyright (C) 2010  Markus Koetter & Tan Kean Siong
#* Copyright (C) 2009  Paul Baecher & Markus Koetter & Mark Schloesser
#*
#* This program is free software; you can redistribute it and/or
#* modify it under the terms of the GNU General Public License
#* as published by the Free Software Foundation; either version 2
#* of the License, or (at your option) any later version.
#*
#* This program is distributed in the hope that it will be useful,
#* but WITHOUT ANY WARRANTY; without even the implied warranty of
#* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#* GNU General Public License for more details.
#*
#* You should have received a copy of the GNU General Public License
#* along with this program; if not, write to the Free Software
#* Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
#*
#*
#*             contact nepenthesdev@gmail.com
#*
#*******************************************************************************/

from dionaea.core import incident, connection, g_dionaea

import traceback
import hashlib
import logging
import os
import tempfile
import fs.memoryfs
from uuid import UUID, uuid3, uuid1, NAMESPACE_OID

from .include.smbfields import *
from .rpcservices import __shares__
from .include.gssapifields import GSSAPI,SPNEGO, NegTokenTarg
#from .include.ntlmfields import NTLMSSP_Header, NTLM_Negotiate, NTLM_Challenge, NTLMSSP_REQUEST_TARGET, NTLMSSP_NEGOTIATE_OEM, NTLMSSP_NEGOTIATE_LM_KEY
from .include.nt_errors import *
from .include.ntlmfields import *
from .include.packet import Raw
from .include.asn1.ber import BER_len_dec, BER_len_enc, BER_identifier_dec
from .include.asn1.ber import BER_CLASS_APP, BER_CLASS_CON,BER_identifier_enc
from .include.asn1.ber import BER_Exception
from dionaea.util import calculate_doublepulsar_opcode, xor
from collections import OrderedDict
#from . import ransomware_detection as rwd 
from cachetools import TTLCache
import zipfile
import copy
from .extras import SmbConfig

smblog = logging.getLogger('SMB')

STATE_START = 0
STATE_SESSIONSETUP = 1
STATE_TREECONNECT = 2
STATE_NTCREATE = 3
STATE_NTWRITE = 4
STATE_NTREAD = 5

registered_services = {}

conCache = TTLCache(5, 120) 


def register_rpc_service(service):
    uuid = service.uuid
    registered_services[uuid] = service
    

class smbd(connection):
    config = None 
    active_con_count = 0
    max_fs_size = 60000000 



    def __init__ (self, proto="tcp", config=None):
        connection.__init__(self,"tcp")
        self.state = {
            'lastcmd': None,
            'readcount': 0,
            'stop': False,
        }
        self.buf = b''
        self.buf2 = b''  # ms17-010 SMB_COM_TRANSACTION2
        self.outbuf = None
        self.printer = b'' # spoolss file "queue"


        # segmented packets mostly from large write req
        self.segPak = False
        self.segPakLen = 0
        self.buffer = b""
        self.fsSize = 0
        self.SectorsPerAllocationUnit = 8
        self.BytesPerSector = 512
        if smbd.config:
            if self.remote.host in conCache:
                conData = conCache.pop(self.remote.host)
                self.sharesTable = conData["Shares"]
#                self.rwd = conData["Detection"]
            elif not self.remote.host:
                pass
            else:
                self.sharesTable = copy.deepcopy(smbd.config.shares)
#                self.rwd = rwd.RansomwareDetection(self.sharesTable, smbd.config, self.remote.host)

                for share_name in self.sharesTable: 
                    self.sharesTable[share_name]["memfs"] = self.config.get_share_fs(share_name)
                smbd.max_fs_size = self.get_shares_size() + smbd.config.memfs_limit


 
 
        # connection data
        #self.clientID = self.remote.host 
        #self.clientCap = ''
        #self.clientMaxBuffer = None       
        self.sessionTable = {}
        self.treeConTable = {} 
        self.fileOpenTable = {}
        #self.isSigningActive = False
        #self.conSessionKey = ''
        #self.sessionSetupRecv = False


      
        
    def apply_config(self, config=None):
        # Avoid import loops
        #from .extras import SmbConfig
        smbd.config = SmbConfig(config=config)


        # Set the global OS_TYPE value
        # ToDo: This is a quick and dirty hack
        from . import rpcservices
        rpcservices.__shares__ = smbd.config.shares
        #self.sharesTable = self.config.shares
        #rpcservices.__shares__ = self.config.shares
        rpcservices.OS_TYPE = smbd.config.os_type

       
    def handle_established(self):
        #		self.timeouts.sustain = 120
        self.timeouts.idle = 120
#		self._in.accounting.limit  = 2000*1024
#		self._out.accounting.limit = 2000*1024
        self.processors()

    def handle_io_in(self,data):
        msg = data

        # large write requests are segmented -> buffer till we have everything
        p = NBTSession(data[:4])
        if len(data) < (p.LENGTH+4) or self.segPak == True:
            if self.segPakLen == 0:
                self.segPak = True
                self.segPakLen = p.LENGTH
                self.buffer = b""

            #we probably do not have the whole packet yet -> return 0

            #smblog.debug('SMB did not get enough data - fragmeneted packet possibly')
            self.buffer += data

            if len(self.buffer) == self.segPakLen+4:
                msg = self.buffer
                self.segPakLen = 0
                self.buffer = b""
                self.segPak = False
            else:
                return len(data) 

        try:
            p = NBTSession(msg)
        except:
            t = traceback.format_exc()
            smblog.error(t)
            return len(data)

#        if len(data) < (p.LENGTH+4):
#            #we probably do not have the whole packet yet -> return 0
#            smblog.info('=== SMB did not get enough data')
#            return 0

        if p.TYPE == 0x81:
            self.send(NBTSession(TYPE=0x82).build())
            return len(data)
        elif p.TYPE != 0:
            # we currently do not handle anything else
            return len(data)

        if p.haslayer(SMB_Header) and p[SMB_Header].Start != b'\xffSMB':
            # not really SMB Header -> bail out
            smblog.error('=== not really SMB')
            self.close()
            return len(data)

        p.show()
        r = None
        
        supCmd = [
            SMB_COM_DELETE_DIRECTORY       ,
            #SMB_COM_OPEN                   ,
            #SMB_COM_CREATE                 ,
            SMB_COM_CLOSE                  ,
            #SMB_COM_FLUSH                  ,
            SMB_COM_DELETE                 ,
            SMB_COM_RENAME                 ,
            #SMB_COM_QUERY_INFORMATION      ,
            #SMB_COM_SET_INFORMATION        ,
            #SMB_COM_READ                   ,
            SMB_COM_WRITE                  ,
            #SMB_COM_LOCK_BYTE_RANGE        ,
            #SMB_COM_UNLOCK_BYTE_RANGE      ,
            #SMB_COM_CREATE_TEMPORARY       ,
            #SMB_COM_CREATE_NEW             ,
            #SMB_COM_CHECK_DIRECTORY        ,
            #SMB_COM_PROCESS_EXIT           ,
            #SMB_COM_SEEK                   ,
            #SMB_COM_LOCK_AND_READ          ,
            #SMB_COM_WRITE_AND_UNLOCK       ,
            #SMB_COM_READ_RAW               ,
            #SMB_COM_READ_MPX               ,
            #SMB_COM_READ_MPX_SECONDARY     ,
            #SMB_COM_WRITE_RAW              ,
            #SMB_COM_WRITE_MPX              ,
            #SMB_COM_WRITE_MPX_SECONDARY    ,
            #SMB_COM_WRITE_COMPLETE         ,
            #SMB_COM_QUERY_SERVER           ,
            #SMB_COM_SET_INFORMATION2       ,
            #SMB_COM_QUERY_INFORMATION2     ,
            #SMB_COM_LOCKING_ANDX           ,
            SMB_COM_TRANSACTION            ,
            SMB_COM_TRANSACTION_SECONDARY  ,
            #SMB_COM_IOCTL                  ,
            #SMB_COM_IOCTL_SECONDARY        ,
            #SMB_COM_COPY                   ,
            #SMB_COM_MOVE                   ,
            SMB_COM_ECHO                   ,
            #SMB_COM_WRITE_AND_CLOSE        ,
            SMB_COM_OPEN_ANDX              ,
            SMB_COM_READ_ANDX              ,
            SMB_COM_WRITE_ANDX             ,
            #SMB_COM_NEW_FILE_SIZE          ,
            #SMB_COM_CLOSE_AND_TREE_DISC    ,
            SMB_COM_TRANSACTION2           ,
            SMB_COM_TRANSACTION2_SECONDARY ,
            #SMB_COM_FIND_CLOSE2            ,
            #SMB_COM_FIND_NOTIFY_CLOSE      ,
            #SMB_COM_TREE_CONNECT           ,
            SMB_COM_TREE_DISCONNECT        ,
            SMB_COM_NEGOTIATE              ,
            SMB_COM_SESSION_SETUP_ANDX     ,
            SMB_COM_LOGOFF_ANDX            ,
            SMB_COM_TREE_CONNECT_ANDX      ,
            #SMB_COM_QUERY_INFORMATION_DISK ,
            #SMB_COM_SEARCH                 ,
            #SMB_COM_FIND                   ,
            #SMB_COM_FIND_UNIQUE            ,
            #SMB_COM_FIND_CLOSE             ,
            SMB_COM_NT_TRANSACT            ,
            #SMB_COM_NT_TRANSACT_SECONDARY  ,
            SMB_COM_NT_CREATE_ANDX         ,
            #SMB_COM_NT_CANCEL              ,
            #SMB_COM_NT_RENAME              ,
            #SMB_COM_OPEN_PRINT_FILE        ,
            #SMB_COM_WRITE_PRINT_FILE       ,
            #SMB_COM_CLOSE_PRINT_FILE       ,
            #SMB_COM_GET_PRINT_QUEUE        ,
            #SMB_COM_READ_BULK              ,
            #SMB_COM_WRITE_BULK             ,
            #SMB_COM_WRITE_BULK_DATA        ,
            SMB_COM_NONE                   ,
        ]
 
        reqHeader = p.getlayer(SMB_Header)
        if not reqHeader.Command in supCmd:
            smblog.error('Not supported SMB Command: %s.' % reqHeader.Command)
            p.show()
            r = SMB_Error_Response()
            header = SMB_Header()
            header.MID = reqHeader.MID 
            header.PID = reqHeader.PID 
            header.TID = reqHeader.TID 
            header.UID = reqHeader.UID 
            header.Command = reqHeader.Command
            header.Status = STATUS_NOT_IMPLEMENTED
            header.Flags = reqHeader.Flags | SMB_FLAGS_REQUEST_RESPONSE
            header.Flags2 = reqHeader.Flags2
            r = NBTSession()/header/r
            self.send(r.build())
            return len(data)

        

        # this is one of the things you have to love, it violates the spec, but
        # has to work ...
        if p.haslayer(SMB_Sessionsetup_ESEC_AndX_Request) and p.getlayer(SMB_Sessionsetup_ESEC_AndX_Request).WordCount == 13:
            smblog.debug("recoding session setup request!")
            p.getlayer(SMB_Header).decode_payload_as(
                SMB_Sessionsetup_AndX_Request2)
            x = p.getlayer(SMB_Sessionsetup_AndX_Request2)
            x.show()

        r = self.process(p)
        smblog.debug("packet: %s" % p.summary())

        if p.haslayer(Raw):
            smblog.warning("p.haslayer(Raw): %s" % p.getlayer(Raw).build())
            p.show()

#		i = incident("dionaea.module.python.smb.info")
#		i.con = self
#		i.direction = 'in'
#		i.data = p.summary()
#		i.report()

        if self.state['stop']:
            smblog.info("faint death.")
            return len(data)

        if r:
            smblog.debug("response: %s" % r.summary())
            #r.show()

#			i = incident("dionaea.module.python.smb.info")
#			i.con = self
#			i.direction = 'out'
#			i.data = r.summary()
#			i.report()

#			r.build()
            #r.show2()
            self.send(r.build())
        else:
            smblog.error('process() returned None.')

        if p.haslayer(Raw):
            smblog.warning("p.haslayer(Raw): %s" % p.getlayer(Raw).build())
            p.show()
            # some rest seems to be not parsed correctly
            # could be start of some other packet, junk, or failed packet dissection
            # TODO: recover from this...
            return len(data) - len(p.getlayer(Raw).load)

        return len(data)

    def process(self, p):

        r = ''
        rp = None
#		self.state['readcount'] = 0
        # if self.state == STATE_START and p.getlayer(SMB_Header).Command ==
        # 0x72:
        rstatus = 0
        Command = p.getlayer(SMB_Header).Command
        
        reqHeader = p.getlayer(SMB_Header)
        smbh = SMB_Header()
        smbh.Command = Command
        smbh.Flags2 = reqHeader.Flags2
#       smbh.Flags2 = p.getlayer(SMB_Header).Flags2 & ~SMB_FLAGS2_EXT_SEC
        smbh.MID = reqHeader.MID
        smbh.PID = reqHeader.PID
        smbh.TID = reqHeader.TID

        
        if Command == SMB_COM_NEGOTIATE:
            if smbd.active_con_count >= smbd.config.active_con_limit:
                smbh.Status = STATUS_INSUFF_SERVER_RESOURCES
                r = SMB_Error_Response()
                r = NBTSession()/smbh/r
                return r
            smbd.active_con_count += 1
            # Negociate Protocol -> Send response that supports minimal features in NT LM 0.12 dialect
            # (could be randomized later to avoid detection - but we need more dialects/options support)
            r = SMB_Negociate_Protocol_Response(
                OemDomainName=smbd.config.oem_domain_name,  # + "\0",
                ServerName=smbd.config.server_name  # + "\0"
            )
            # we have to select dialect
            c = 0
            tmp = p.getlayer(SMB_Negociate_Protocol_Request_Counts)
            while c < len(tmp.Requests):
                request = tmp.Requests[c]
                if request.BufferData.find('NT LM 0.12') != -1:
                    break
                c += 1

            r.DialectIndex = c


#			r.Capabilities = r.Capabilities & ~CAP_EXTENDED_SECURITY
            if not p.Flags2 & SMB_FLAGS2_EXT_SEC:
                r.Capabilities = r.Capabilities & ~CAP_EXTENDED_SECURITY

        # elif self.state == STATE_SESSIONSETUP and
        # p.getlayer(SMB_Header).Command == 0x73:
        elif Command == SMB_COM_SESSION_SETUP_ANDX:
            if p.haslayer(SMB_Sessionsetup_ESEC_AndX_Request):
                r = SMB_Sessionsetup_ESEC_AndX_Response(
                    NativeOS=smbd.config.native_os,
                    NativeLanManager=smbd.config.native_lan_manager,
                    PrimaryDomain=smbd.config.primary_domain
                )
                #self.clientCaps = p.getlayer(SMB_Sessionsetup_ESEC_AndX_Request).Capabilities
                ntlmssp = None
                sb = p.getlayer(
                    SMB_Sessionsetup_ESEC_AndX_Request).SecurityBlob

                if sb.startswith(b"NTLMSSP"):
                    # GSS-SPNEGO without OID
                    ntlmssp = NTLMSSP_Header(sb)
                    ntlmssp.show()
                    # FIXME what is a proper reply?
                    # currently there windows calls Sessionsetup_AndX2_request
                    # after this one with bad reply
                    if ntlmssp.MessageType == 1:
                        r.Action = 0
                        ntlmnegotiate = ntlmssp.getlayer(NTLM_Negotiate)
                        rntlmssp = NTLMSSP_Header(MessageType=2)
                        rntlmchallenge = NTLM_Challenge(
                            NegotiateFlags=ntlmnegotiate.NegotiateFlags)
                        rntlmchallenge.ServerChallenge = b"\xa4\xdf\xe8\x0b\xf5\xc6\x1e\x3a"

                        if ntlmnegotiate.NegotiateFlags & NTLMSSP_REQUEST_TARGET:
                            rntlmchallenge.TargetNameFields.Offset = 56 
                            rntlmchallenge.Payload = b"\x58\x00\x48\x00\x4e\x00\x37\x00"
                            rntlmchallenge.TargetNameFields.Len = len(rntlmchallenge.Payload)
                            rntlmchallenge.TargetNameFields.MaxLen = len(rntlmchallenge.Payload)

                        if ntlmnegotiate.NegotiateFlags & NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY:
                            rntlmchallenge.TargetInfoFields.Offset = 56 + len(rntlmchallenge.Payload)
                            nbName = b"\x54\x00\x43\x00\x4e\x00\x37\x00"
                            nbDomainName = b"\x55\x00\x4e\x00\x37\x00"
                            rntlmchallenge.AVPair1 = AV_PAIR(Id = 1, Len = len(nbName), Value = nbName)
                            rntlmchallenge.AVPair2 = AV_PAIR(Id = 2, Len = len(nbDomainName), Value = nbDomainName)
                            rntlmchallenge.AVPair3 = AV_PAIR(Id = 0)
                            rntlmchallenge.NegotiateFlags |= NTLMSSP_NEGOTIATE_TARGET_INFO 
                            rntlmchallenge.TargetInfoFields.Len = (rntlmchallenge.AVPair1.size()+rntlmchallenge.AVPair2.size()+rntlmchallenge.AVPair3.size())
                            rntlmchallenge.TargetInfoFields.MaxLen = rntlmchallenge.TargetInfoFields.Len 

                        rntlmchallenge.NegotiateFlags &= ~NTLMSSP_NEGOTIATE_OEM
                        rntlmchallenge.NegotiateFlags &= ~NTLMSSP_NEGOTIATE_LM_KEY
                        rntlmchallenge.NegotiateFlags &= ~NTLMSSP_NEGOTIATE_56
                        #rntlmchallenge.NegotiateFlags |= NTLMSSP_TARGET_TYPE_SERVER
                        #rntlmchallenge.NegotiateFlags &= ~NTLMSSP_REQUEST_TARGET

                        rntlmssp = rntlmssp / rntlmchallenge
                        rntlmssp.show()
                        raw = rntlmssp.build()
                        r.SecurityBlob = raw
                        rstatus = 0xc0000016 # STATUS_MORE_PROCESSING_REQUIRED
                    elif ntlmssp.MessageType == 3:
                        r.Action = 1

                        uid = len(self.sessionTable.keys())
                        smbh.UID = uid
                        self.sessionTable[uid] = {
                            "IsAnonymous": True,
                            "UID": uid,
                            "UserName": "" ,
                            "CreationTime": "",
                            "IdleTime": "",
                        }
                        smblog.info('Guest session established')

                elif sb.startswith(b"\x04\x04") or sb.startswith(b"\x05\x04"):
                    # GSSKRB5 CFX wrapping
                    # FIXME is this relevant at all?
                    pass
                else:
                    # (hopefully) the SecurityBlob is prefixed with
                    # * BER encoded identifier
                    # * BER encoded length of the data
                    cls,pc,tag,sb = BER_identifier_dec(sb)
                    l,sb = BER_len_dec(sb)
                    if cls == BER_CLASS_APP and pc > 0 and tag == 0:
                        # NTLM NEGOTIATE
                        #
                        # reply NTML CHALLENGE
                        # SMB_Header.Status = STATUS_MORE_PROCESSING_REQUIRED
                        # SMB_Sessionsetup_ESEC_AndX_Response.SecurityBlob is
                        # \xa1 BER_length NegTokenTarg where
                        # NegTokenTarg.responseToken is NTLM_Header / NTLM_Challenge
                        gssapi = GSSAPI(sb)
                        sb = gssapi.getlayer(Raw).load
                        cls,pc,tag,sb = BER_identifier_dec(sb)
                        l,sb = BER_len_dec(sb)
                        spnego = SPNEGO(sb)
                        spnego.show()
                        sb = spnego.NegotiationToken.mechToken.__str__()
                        try:
                            cls,pc,tag,sb = BER_identifier_dec(sb)
                        except BER_Exception as e:
                            smblog.warning("BER Exception", exc_info=True)
                            return rp
                        l,sb = BER_len_dec(sb)
                        ntlmssp = NTLMSSP_Header(sb)
                        ntlmssp.show()
                        if ntlmssp.MessageType == 1:
                            r.Action = 0
                            ntlmnegotiate = ntlmssp.getlayer(NTLM_Negotiate)
                            rntlmssp = NTLMSSP_Header(MessageType=2)
                            rntlmchallenge = NTLM_Challenge(
                                NegotiateFlags=ntlmnegotiate.NegotiateFlags)
                            rntlmchallenge.TargetInfoFields.Offset = rntlmchallenge.TargetNameFields.Offset = 0x30
#							if ntlmnegotiate.NegotiateFlags & NTLMSSP_REQUEST_TARGET:
#								rntlmchallenge.TargetNameFields.Offset = 0x38
#								rntlmchallenge.TargetNameFields.Len = 0x1E
#								rntlmchallenge.TargetNameFields.MaxLen = 0x1E
                            rntlmchallenge.ServerChallenge = b"\xa4\xdf\xe8\x0b\xf5\xc6\x1e\x3a"
                            if ntlmnegotiate.NegotiateFlags & NTLMSSP_REQUEST_TARGET:
                                rntlmchallenge.TargetNameFields.Offset = rntlmchallenge.size() + rntlmssp.size() 
                                rntlmchallenge.Payload = b"\x58\x00\x48\x00\x4e\x00\x37\x00"
                                #rntlmchallenge.Payload = (b"Win7")
                                rntlmchallenge.TargetNameFields.Len = len(rntlmchallenge.Payload)
                                rntlmchallenge.TargetNameFields.MaxLen = len(rntlmchallenge.Payload)

                            if ntlmnegotiate.NegotiateFlags & NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY:
                                rntlmchallenge.TargetInfoFields.Offset = 56 + len(rntlmchallenge.Payload)
                                nbName = b"\x54\x00\x43\x00\x4e\x00\x37\x00"
                                nbDomainName = b"\x55\x00\x4e\x00\x37\x00"
                                rntlmchallenge.AVPair1 = AV_PAIR(Id = 1, Len = len(nbName), Value = nbName)
                                rntlmchallenge.AVPair2 = AV_PAIR(Id = 2, Len = len(nbDomainName), Value = nbDomainName)
                                rntlmchallenge.AVPair3 = AV_PAIR(Id = 0)
                                rntlmchallenge.NegotiateFlags |= NTLMSSP_NEGOTIATE_TARGET_INFO 
                                rntlmchallenge.TargetInfoFields.Len = (rntlmchallenge.AVPair1.size()+rntlmchallenge.AVPair2.size()+rntlmchallenge.AVPair3.size())
                                rntlmchallenge.TargetInfoFields.MaxLen = rntlmchallenge.TargetInfoFields.Len 

                            rntlmchallenge.NegotiateFlags &= ~NTLMSSP_NEGOTIATE_OEM
                            rntlmchallenge.NegotiateFlags &= ~NTLMSSP_NEGOTIATE_LM_KEY
                            rntlmchallenge.NegotiateFlags &= ~NTLMSSP_NEGOTIATE_56
 
                            rntlmssp = rntlmssp / rntlmchallenge
                            rntlmssp.show()
                            negtokentarg = NegTokenTarg(
                                negResult=1,supportedMech='1.3.6.1.4.1.311.2.2.10')
                            negtokentarg.responseToken = rntlmssp.build()
                            negtokentarg.mechListMIC = None
                            raw = negtokentarg.build()
                            #r.SecurityBlob = b'\xa1' + BER_len_enc(len(raw)) + raw
                            r.SecurityBlob = BER_identifier_enc(
                                BER_CLASS_CON,1,1) + BER_len_enc(len(raw)) + raw
                            # STATUS_MORE_PROCESSING_REQUIRED
                            rstatus = 0xc0000016
                    elif cls == BER_CLASS_CON and pc == 1 and tag == 1:
                        # NTLM AUTHENTICATE
                        #
                        # reply
                        # \xa1 BER_length NegTokenTarg('accepted')
                        negtokentarg = NegTokenTarg(sb)
                        negtokentarg.show()
                        ntlmssp = NTLMSSP_Header(
                            negtokentarg.responseToken.val)
                        ntlmssp.show()
                        rnegtokentarg = NegTokenTarg(
                            negResult=0, supportedMech=None)
                        raw = rnegtokentarg.build()
                        #r.SecurityBlob = b'\xa1' + BER_len_enc(len(raw)) + raw
                        r.SecurityBlob = BER_identifier_enc(
                            BER_CLASS_CON,1,1) + BER_len_enc(len(raw)) + raw

                        # create session after successfull authentication
                        uid = len(self.sessionTable.keys())
                        smbh.UID = uid
                        self.sessionTable[uid] = {
                            "IsAnonymous": False,
                            "UID": uid,
                            "UserName": "" ,
                            "CreationTime": "",
                            "IdleTime": "",
                        }
                        smblog.info('Guest session established')


            elif p.haslayer(SMB_Sessionsetup_AndX_Request2):
                r = SMB_Sessionsetup_AndX_Response2(
                    NativeOS=smbd.config.native_os,
                    NativeLanManager=smbd.config.native_lan_manager,
                    PrimaryDomain=smbd.config.primary_domain,
                    Action=0,
                    AndXOffset=209,
                )
                uid = len(self.sessionTable.keys())
                smbh.UID = uid
                self.sessionTable[uid] = {
                    "IsAnonymous": True,
                    "UID": uid,
                    "UserName": "",
                    "CreationTime": "",
                    "IdleTime": "",
                }
                smblog.info('Guest session established')

            else:
                smblog.warn("Unknown Session Setup Type used")

        elif Command == SMB_COM_TREE_CONNECT_ANDX:
            reqParam = p.getlayer(SMB_Treeconnect_AndX_Request)
            if reqParam.Flags & 0x0008:
                respParam = SMB_Treeconnect_AndX_Response_Extended()
            else:
                respParam = SMB_Treeconnect_AndX_Response()

            # get Path as ascii string
            #f, v = reqParam.getfield_and_val("Path")
            #shareName = f.i2repr(reqParam, v)
            shareName = reqParam.Path
            #shareName = shareName.strip("\x00")
            #shareName = shareName.strip(" ")
            shareName = shareName.split('\\')[-1]

            #if shareName == 'ADMIN$' or shareName == 'C$':
            #    rstatus = 0xc0000022  # STATUS_ACCESS_DENIED
            #    smblog.warn('Connection attempt to hidden admin share')
            # support for CVE-2017-7494 Samba SMB RCE
#            elif h.Path[-6:] == b'share\0':
#                smblog.critical('Possible CVE-2017-7494 Samba SMB RCE attempts..')
#                r.AndXOffset = 0
#                r.Service = "A:\0"
#                r.NativeFileSystem = "NTFS\0"
            for sh in self.sharesTable:
                print(sh)
            print(shareName)
            if shareName in self.sharesTable:
                share = self.sharesTable[shareName]
                respParam.NativeFileSystem = share["nativefs"]
                respParam.Service = share["service"] 
                
                tid = len(self.treeConTable.keys()) 
                self.treeConTable[tid] = {
                    "Share": share, 
                    "Session": self.sessionTable[reqHeader.UID],
                    "OpenCount": 0,
                    "CreationTime": "",
                }
                #self.sharesTable[shareName]["CurrentUses"] += 1
                smbh.TID=tid          
                smblog.info('Connection to share %s' % shareName)
                                
               # if self.sharesTable[shareName]["service"] != reqParam.Service:
               #     respParam = SMB_Error_Response()
               #     rstatus = STATUS_BAD_DEVICE_TYPE

            else:
                respParam = SMB_Error_Response()
                rstatus = STATUS_OBJECT_PATH_NOT_FOUND 

            r = respParam

#            elif h.Path[-6:] == b'share\0':
#                smblog.info('Possible CVE-2017-7494 Samba SMB RCE attempts..')
#                r.AndXOffset = 0
#                r.Service = "A:\0"
#                r.NativeFileSystem = "NTFS\0"
        elif Command == SMB_COM_TREE_DISCONNECT:
            self.treeConTable.pop(reqHeader.TID, None) 
            r = SMB_Treedisconnect()
        elif Command == SMB_COM_CLOSE:
            reqParam = p.getlayer(SMB_Close)
            if reqParam.FID in self.fileOpenTable and self.fileOpenTable[reqParam.FID] is not None:
                #fileobj = self.fileOpenTable[p.FID]
                #icd = incident("dionaea.download.complete")
                #icd.path = self.fileOpenTable[reqParam.FID]["FileName"] 
                #icd.url = "smb://" + self.remote.host
                #icd.con = self
                #icd.report()
                #self.fileOpenTable[p.FID].unlink(self.fileOpenTable[p.FID].name)
                if self.fileOpenTable[reqParam.FID]["Type"] == SMB_RES_DISK and self.fileOpenTable[reqParam.FID]["Handle"] != -1:
                    self.fileOpenTable[reqParam.FID]["Handle"].close()

                    fileName = self.fileOpenTable[reqParam.FID]["FileName"]
                    share = self.treeConTable[reqHeader.TID]["Share"]["name"]
#                    self.rwd.new_file_op(rwd.FILE_OP_CLOSE, fileName, share)
 
                    if self.fileOpenTable[reqParam.FID]["DeletePending"]:
#                        self.rwd.new_file_op(rwd.FILE_OP_DELETE, fileName, share)
                       
                        memFS = self.treeConTable[reqHeader.TID]["Share"]["memfs"]
                        memFS.remove(fileName)
                self.fileOpenTable.pop(reqParam.FID, None)
            else:
                rstatus = STATUS_INVALID_HANDLE
            r = SMB_Close_Response()
#            r = p.getlayer(SMB_Close)
#            if p.FID in self.fids and self.fids[p.FID] is not None:
#                self.fids[p.FID].close()
#                fileobj = self.fids[p.FID]
#                icd = incident("dionaea.download.complete")
#                icd.path = fileobj.name
#                icd.url = "smb://" + self.remote.host
#                icd.con = self
#                icd.report()
#                os.unlink(self.fids[p.FID].name)
#                del self.fids[p.FID]
#                r = SMB_Close_Response()
        elif Command == SMB_COM_LOGOFF_ANDX:
            r = SMB_Logoff_AndX()
        elif Command == SMB_COM_NT_CREATE_ANDX:
            # FIXME return NT_STATUS_OBJECT_NAME_NOT_FOUND=0xc0000034
            # for writes on IPC$
            # this is used to distinguish between file shares and devices by nmap smb-enum-shares
            # requires mapping of TreeConnect ids to names/objects

            reqParam = p.getlayer(SMB_NTcreate_AndX_Request)
            if reqParam.CreateFlags & SMB_CREATEFL_EXT_RESP:
                resp = SMB_NTcreate_AndX_Response_Extended()
            else:
                resp = SMB_NTcreate_AndX_Response()
             #     rootfid !=0: filename path is relative to rootfid
            if reqHeader.RootFID != 0:
                pass

#            f,v = reqParam.getfield_and_val("FileName")
#            fileName = f.i2repr(reqParam,v)
            fileName = reqParam.FileName
            fileName = fileName.replace("\\", "/")
            fid = 0x4000 
            while fid in self.fileOpenTable.keys():
                fid += 1
 
            if self.treeConTable[reqHeader.TID]["Share"]["service"] == SMB_SERVICE_NAMED_PIPE:
                resp.CreateAction = SMB_CREATDISP_FILE_OPEN
                resp.FileType = SMB_RES_MSG_MODE_PIPE 
        # nonblocking,consumer end,msg pipe, read msg from pipe, ICount=255
                resp.IPCstate = 0x05ff 
                resp.FID = fid
                resp.IsDirectory = 0
                self.fileOpenTable[fid] = {
                        "Handle": -1, 
                        "Type": SMB_RES_MSG_MODE_PIPE,
                        "FileName": fileName, 
                        "DeletePending": 0,
                }              
                smblog.info('Opening named pipe %s' % fileName)
                if fileName == "/MsFteWds" or fileName == "/wkssvc":
                    rstatus = STATUS_PIPE_DISCONNECTED
                    resp = SMB_Error_Response()
                    #resp.CreateAction = SMB_CREATDISP_FILE_OVERWRITE_IF
                    #resp.FileType = SMB_RES_MSG_MODE_PIPE 
                    #resp.IPCstate = 0x0000 # nonblocking,consumer end,msg pipe, read msg from pipe, ICount=255
                    #fid = 0x4000 + len(self.fileOpenTable.keys()) 
                    #resp.FID = fid 
                    #resp.IsDirectory = 0
                    #self.fileOpenTable[fid] = {
                    #        "Handle": -1, 
                    #        "Type": SMB_RES_MSG_MODE_PIPE,
                    #        "FileName": fileName, 
                    #}              


            else:
                memFS = self.treeConTable[reqHeader.TID]["Share"]["memfs"]
                # file CreateDisposition/Action 
                mode = "" 
                createAction = SMB_CREATDISP_FILE_CREATE
                disp = reqParam.Disposition
                if memFS.exists(fileName):
                    if disp == SMB_CREATDISP_FILE_SUPERSEDE:
                        mode = "wr" 
                        createAction = SMB_CREATDISP_FILE_SUPERSEDE
                    elif disp == SMB_CREATDISP_FILE_OVERWRITE_IF or disp == SMB_CREATDISP_FILE_OVERWRITE:
                        mode = "wr" 
                        createAction = SMB_CREATDISP_FILE_OPEN_IF
                    elif disp == SMB_CREATDISP_FILE_OPEN_IF or disp == SMB_CREATDISP_FILE_OPEN:
                        mode = "ar"
                        createAction = SMB_CREATDISP_FILE_OPEN
                    elif disp == SMB_CREATDISP_FILE_CREATE:
                        rstatus = STATUS_OBJECT_NAME_COLLISION
                else:
                    if disp == SMB_CREATDISP_FILE_SUPERSEDE or disp == SMB_CREATDISP_FILE_OVERWRITE_IF or disp == SMB_CREATDISP_FILE_OPEN_IF or disp == SMB_CREATDISP_FILE_CREATE:
                        mode = "xwr"
                        createAction = SMB_CREATDISP_FILE_CREATE
                    elif disp == SMB_CREATDISP_FILE_OVERWRITE or disp == SMB_CREATDISP_FILE_OPEN:
                        # maybe STATUS_OBJECT_NAME_NOT_FOUND
                        #rstatus = STATUS_NO_SUCH_FILE
                        rstatus = STATUS_OBJECT_NAME_NOT_FOUND 

                    # requested/granted access rights to the object
                    # TODO 0x00000000 query attr without accessing file
#                    desiredAccess = reqParam.AccessMask
#                    if (desiredAccess & SMB_AM_READ) or (desiredAccess & SMB_AM_GENERIC_READ):
#                        mode += "r" 
#                    if (desiredAccess & SMB_AM_WRITE) or (desiredAccess & SMB_AM_GENERIC_WRITE):
#                        if (desiredAccess & SMB_AM_READ) or (desiredAccess & SMB_AM_GENERIC_READ):
#                            mode += "ar" 
#                        else:
#                            mode += "r" 
#                    if (desiredAccess & SMB_AM_GENERIC_ALL):
#                        mode += "wr"

                if rstatus == STATUS_SUCCESS:
                    fileHandle = None
                    if memFS.isdir(fileName):
                        if reqParam.CreateOptions & SMB_CREATOPT_NONDIRECTORY:
                            rstatus = STATUS_FILE_IS_A_DIRECTORY
                        else:
                            fileHandle = -1
                            createAction = SMB_CREATDISP_FILE_OPEN
                            resp.FileAttributes = SMB_FA_DIRECTORY
                            #smblog.info("OPEN Folder! %s" % fileName)
                    # TODO what happens when a file exists and CREATOPT_DIR is set
                    elif (reqParam.CreateOptions & SMB_CREATOPT_DIRECTORY) and not memFS.exists(fileName):
                        try:
                            memFS.makedirs(fileName)
                            fileHandle = -1
                            resp.FileAttributes = SMB_FA_DIRECTORY
                            createAction = SMB_CREATDISP_FILE_CREATE
                            #smblog.info("OPEN Folder! %s" % fileName)
                        except Exception:
                            rstatus = STATUS_ACCESS_DENIED
                    else:
                        op = None
#                        if createAction == SMB_CREATDISP_FILE_SUPERSEDE or createAction == SMB_CREATDISP_FILE_OPEN_IF:
#                            op = rwd.FILE_OP_TRUNC
#                        if createAction == SMB_CREATDISP_FILE_OPEN:
#                            op = rwd.FILE_OP_OPEN
#                        if createAction == SMB_CREATDISP_FILE_CREATE:
#                            op = rwd.FILE_OP_CREATE
#                        if op:
#                            share = self.treeConTable[reqHeader.TID]["Share"]["name"]
#                            self.rwd.new_file_op(op, fileName, share)

                        fileHandle = memFS.openbin(fileName, mode)
                        #smblog.info("OPEN FILE! %s" % fileName)

                # compile response
                if rstatus == STATUS_SUCCESS:
                    resp.FID = fid
                    resp.IsDirectory = memFS.isdir(fileName)
                    resp.CreateAction = createAction
                    #resp.IPCstate = 0 if memFS.isdir(fileName) else 7
                    resp.AllocationSize = memFS.getsize(fileName)
                    resp.EndOfFile = memFS.getsize(fileName)
                    resp.FileType = 0 # Directory or file
                    resp.OpLockLevel = (reqParam.CreateFlags&0b00000110)>>1
                    details = memFS.getinfo(fileName, namespaces=["details"])
                    resp.Created = details.created
                    resp.LastAccess = details.accessed
                    resp.LastWrite = details.modified
                    resp.Change = details.modified
                    #resp.FileAttributes = 0x00000000
                    self.fileOpenTable[fid] = {
                            "Handle": fileHandle,
                            "Type": SMB_RES_DISK,
                            "FileName": fileName,
                            "DeletePending": 0,
                    }
                else:
                    resp = SMB_Error_Response()

            r = resp
#            if h.FileAttributes & (SMB_FA_HIDDEN|SMB_FA_SYSTEM|SMB_FA_ARCHIVE|SMB_FA_NORMAL):
#                # if a normal file is requested, provide a file
#
#                dionaea_config = g_dionaea.config().get("dionaea")
#                download_dir = dionaea_config.get("download.dir")
#                download_suffix = dionaea_config.get("download.suffix", ".tmp")
#                self.fileOpenTable[r.FID] = tempfile.NamedTemporaryFile(
#                    delete=False,
#                    prefix="smb-",
#                    suffix=download_suffix,
#                    dir=download_dir
#                )
#
#                # get pretty filename
#                f,v = h.getfield_and_val('Filename')
#                filename = f.i2repr(h,v)
#                for j in range(len(filename)):
#                    if filename[j] != '\\' and filename[j] != '/':
#                        break
#                filename = filename[j:]
#
#                i = incident("dionaea.download.offer")
#                i.con = self
#                i.url = "smb://%s/%s" % (self.remote.host, filename)
#                i.report()
#                smblog.info("OPEN FILE! %s" % filename)
#
#            elif h.FileAttributes & SMB_FA_DIRECTORY:
#                pass
#            else:
#                self.fileOpenTable[r.FID] = None
        elif Command == SMB_COM_OPEN_ANDX:
            h = p.getlayer(SMB_Open_AndX_Request)
            r = SMB_Open_AndX_Response()
            r.FID = 0x4000
            while r.FID in self.fileOpenTable:
                r.FID += 0x200

            dionaea_config = g_dionaea.config().get("dionaea")
            download_dir = dionaea_config.get("download.dir")
            download_suffix = dionaea_config.get("download.suffix", ".tmp")

            self.fileOpenTable[r.FID] = tempfile.NamedTemporaryFile(
                delete=False,
                prefix="smb-",
                suffix=download_suffix,
                dir=download_dir
            )

            # get pretty filename
            f,v = h.getfield_and_val('FileName')
            filename = f.i2repr(h,v)
            for j in range(len(filename)):
                if filename[j] != '\\' and filename[j] != '/':
                    break
            filename = filename[j:]

            i = incident("dionaea.download.offer")
            i.con = self
            i.url = "smb://%s/%s" % (self.remote.host, filename)
            i.report()
            #smblog.info("OPEN FILE! %s" % filename)

        elif Command == SMB_COM_ECHO:
            r = p.getlayer(SMB_Header).payload
        elif Command == SMB_COM_WRITE_ANDX:
            r = SMB_Write_AndX_Response()
            reqParam = p.getlayer(SMB_Write_AndX_Request)

            memFS = self.treeConTable[reqHeader.TID]["Share"]["memfs"]
            if reqParam.FID in self.fileOpenTable and self.fileOpenTable[reqParam.FID] is not None:
                if self.fileOpenTable[reqParam.FID]["Type"] == SMB_RES_DISK:
                    #smblog.warn("WRITE FILE! %s"% self.fileOpenTable[reqParam.FID]["FileName"])
                    if len(reqParam.Data) > reqParam.DataLenLow:
                        # return error
                        pass

                    offset = reqParam.Offset
                    if reqParam.WordCount == 0x0e:
                        offset = (reqParam.HighOffset<<32)|reqParam.Offset

                    byteCountToWrite = (reqParam.DataLenHigh<<16)|reqParam.DataLenLow
                    share = self.treeConTable[reqHeader.TID]["Share"]
                    fileName = self.fileOpenTable[reqHeader.FID]["FileName"]
                    add_bytes = share["memfs"].getsize(fileName)-(offset+byteCountToWrite)
                    if add_bytes > 0:
                        add_bytes = 0
                    else:
                        add_bytes = abs(add_bytes)
                    if add_bytes + self.get_shares_size() > smbd.max_fs_size:
                        rstatus = STATUS_DISK_FULL
                        r = SMB_Error_Response()
                        icd = incident("dionaea.smb.memoryfs.full")
                        icd.url = "smb://" + self.remote.host
                        icd.con = self
                        icd.report()
                    else:
#                        if add_bytes:
#                            self.rwd.new_file_op(rwd.FILE_OP_WRITE, fileName, share["name"])
#                        else:
#                            self.rwd.new_file_op(rwd.FILE_OP_OVERWRITE, fileName, share["name"])
                        fileHandle = self.fileOpenTable[reqParam.FID]["Handle"]
                        fileHandle.seek(offset)
                        fileHandle.write(reqParam.Data)
                        bytesWritten = fileHandle.tell() - offset 
                        r.CountLow = bytesWritten % 65536
                        #r.CountHigh = int((bytesWritten - r.CountLow) / 65536 )
                        r.CountHigh = bytesWritten // 65536 
                        r.Remaining = byteCountToWrite - bytesWritten 
                        self.fsSize += add_bytes 

                elif self.fileOpenTable[reqParam.FID]["Type"] == SMB_RES_MSG_MODE_PIPE:
                    self.buf += reqParam.Data
    #				self.process_dcerpc_packet(p.getlayer(SMB_Write_AndX_Request).Data)
                    if len(self.buf) >= 10:
                        # we got the dcerpc header
                        inpacket = DCERPC_Header(self.buf[:10])
                        smblog.debug("got header")
                        inpacket = DCERPC_Header(self.buf)
                        smblog.debug("FragLen %i len(self.buf) %i" %
                                     (inpacket.FragLen, len(self.buf)))
                        if inpacket.FragLen == len(self.buf):
                            outpacket = self.process_dcerpc_packet(self.buf)
                            if outpacket is not None:
                                outpacket.show()
                                #self.outbuf = outpacket.build()
                                self.fileOpenTable[reqParam.FID]["dcerpc_buf"] = outpacket.build() 
                            self.buf = b''
        elif Command == SMB_COM_WRITE:
            h = p.getlayer(SMB_Write_Request)
            if h.FID in self.fileOpenTable and self.fileOpenTable[h.FID] is not None:
                smblog.warn("WRITE FILE!")
                self.fileOpenTable[h.FID].write(h.Data)
#            h = p.getlayer(SMB_Write_AndX_Request)
#            r.CountLow = h.DataLenLow
#            if h.FID in self.fids and self.fids[h.FID] is not None:
#                smblog.warning("WRITE FILE!")
#                self.fids[h.FID].write(h.Data)
#            else:
#                self.buf += h.Data
##				self.process_dcerpc_packet(p.getlayer(SMB_Write_AndX_Request).Data)
#                if len(self.buf) >= 10:
#                    # we got the dcerpc header
#                    inpacket = DCERPC_Header(self.buf[:10])
#                    smblog.debug("got header")
#                    inpacket = DCERPC_Header(self.buf)
#                    smblog.debug("FragLen %i len(self.buf) %i" %
#                                 (inpacket.FragLen, len(self.buf)))
#                    if inpacket.FragLen == len(self.buf):
#                        outpacket = self.process_dcerpc_packet(self.buf)
#                        if outpacket is not None:
#                            outpacket.show()
#                            self.outbuf = outpacket.build()
#                        self.buf = b''
#        elif Command == SMB_COM_WRITE:
#            h = p.getlayer(SMB_Write_Request)
#            if h.FID in self.fids and self.fids[h.FID] is not None:
#                smblog.warning("WRITE FILE!")
#                self.fids[h.FID].write(h.Data)
            r = SMB_Write_Response(CountOfBytesWritten = h.CountOfBytesToWrite)
        elif Command == SMB_COM_READ_ANDX:
            r = SMB_Read_AndX_Response()
            reqParam = p.getlayer(SMB_Read_AndX_Request)

            if not reqParam.FID in self.fileOpenTable:
                r = SMB_Error_Response()
                rstatus = STATUS_INVALID_HANDLE
            elif self.fileOpenTable[reqHeader.FID]["Type"] == SMB_RES_DISK:
                share = self.treeConTable[reqHeader.TID]["Share"]["name"]
                fileName = self.fileOpenTable[reqHeader.FID]["FileName"]
#                self.rwd.new_file_op(rwd.FILE_OP_READ, fileName, share)


                offset = reqParam.Offset
                if reqParam.WordCount == 0x0c:
                    offset = (reqParam.HighOffset<<32)|reqParam.Offset
                
                maxCountHigh = reqParam.Timeout>>16
                maxCount = (maxCountHigh<<16)|reqParam.MaxCountLow

                fileHandle = self.fileOpenTable[reqParam.FID]["Handle"]
                fileHandle.seek(offset) 
                rdata = SMB_Data()
                rdata.Bytes = fileHandle.read(maxCount)
                #rdata.Bytes += (reqParam.MaxCountLow - len(rdata.Bytes)) * b"\x00"
                r.DataLenLow = len(rdata.Bytes) % 65535
                r.DataLenHigh = int((len(rdata.Bytes) - r.DataLenLow) / 65535)
                r /= rdata
                #smblog.info('Read %d bytes from %s'% (len(rdata.Bytes),self.fileOpenTable[reqParam.FID]["FileName"])) 
            else:
                # self.outbuf should contain response buffer now
                #if not self.outbuf:
                if not "dcerpc_buf" in self.fileOpenTable[reqParam.FID]:
                    if self.state['stop']:
                        smblog.debug('drop dead!')
                    else:
                        smblog.error('dcerpc processing failed. bailing out.')
                    return rp
    
                rdata = SMB_Data()
                #outbuf = self.outbuf
                outbuf = self.fileOpenTable[reqParam.FID]["dcerpc_buf"]
                outbuflen = len(outbuf)
                smblog.debug("MaxCountLow %i len(outbuf) %i readcount %i" %(
                    reqParam.MaxCountLow, outbuflen, self.state['readcount']) )
                if reqParam.MaxCountLow < outbuflen-self.state['readcount']:
                    rdata.ByteCount = reqParam.MaxCountLow
                    newreadcount = self.state['readcount']+reqParam.MaxCountLow
                else:
                    newreadcount = 0
                    self.outbuf = None
    
                rdata.Bytes = outbuf[
                    self.state['readcount'] : self.state['readcount'] + reqParam.MaxCountLow ]
                rdata.ByteCount = len(rdata.Bytes)+1
                r.DataLenLow = len(rdata.Bytes)
                smblog.debug("readcount %i len(rdata.Bytes) %i" %
                             (self.state['readcount'], len(rdata.Bytes)) )
                r /= rdata
    
                self.state['readcount'] = newreadcount

        elif Command == SMB_COM_RENAME:
            reqParam = p.getlayer(SMB_Rename_Request)
            resp = SMB_Error_Response()

            memFS = self.treeConTable[reqHeader.TID]["Share"]["memfs"]
                    
            oldFileName = reqParam.OldFileName
            oldFileName = oldFileName.strip("\x00").strip(" ")
            oldFileName = oldFileName.replace("\\", "/")
            searchPattern = oldFileName.split("/")[-1]
            dirPath = oldFileName[:-len(searchPattern)]

            newFileName = reqParam.NewFileName
            newFileName = newFileName.strip("\x00").strip(" ")
            newFileName = newFileName.replace("\\", "/")

            gen = memFS.filterdir(dirPath, files=[searchPattern], dirs=[searchPattern])
            searchResults = [n for n in gen]
            if not searchResults:
                rstatus = STATUS_NO_SUCH_FILE
            if memFS.exists(newFileName):
                rstatus = STATUS_OBJECT_NAME_COLLISION



            includeDir = (SMB_FA_DIRECTORY & reqParam.SearchAttributes) > 0
            includeSys = (SMB_FA_SYSTEM & reqParam.SearchAttributes) > 0
            includeHidden = (SMB_FA_HIDDEN & reqParam.SearchAttributes) > 0
            includeRO = (SMB_FA_READONLY & reqParam.SearchAttributes) > 0
                
            for item in searchResults:
                path = fs.path.join(dirPath, item.name)
                if memFS.isdir(path):
                    if includeDir:
                        memFS.movedir(path, newFileName, create=True)
                    else:
                        rstatus = STATUS_NO_SUCH_FILE
                else:
                    memFS.move(path, newFileName)
                    share = self.treeConTable[reqHeader.TID]["Share"]["name"]
#                    self.rwd.new_file_op(rwd.FILE_OP_RENAME, path, share, new_file_name=newFileName)
                           

            #smblog.info('Move %s to %s' % (oldFileName, newFileName)) 
            r = resp

        elif Command == SMB_COM_TRANSACTION:
            h = p.getlayer(SMB_Trans_Request)
            r = SMB_Trans_Response()
            rdata = SMB_Data()

            TransactionName = h.TransactionName
            if type(TransactionName) == bytes:
                if smbh.Flags2 & SMB_FLAGS2_UNICODE:
                    TransactionName = TransactionName#.decode('utf-16')
                else:
                    TransactionName = TransactionName#.decode('ascii')

            if TransactionName[-1] == '\0':
                TransactionName = TransactionName[:-1]

#			print("'{}' == '{}' => {} {} {}".format(TransactionName, '\\PIPE\\',
#				TransactionName == '\\PIPE\\', type(TransactionName) == type('\\PIPE\\'),
#				len(TransactionName)) )


            if TransactionName == '\\PIPE\\LANMAN':
                # [MS-RAP].pdf - Remote Administration Protocol
                rapbuf = bytes(h.Param)
                rap = RAP_Request(rapbuf)
                rap.show()
                rout = RAP_Response()
                coff = 0
                if rap.Opcode == RAP_OP_NETSHAREENUM:
                    (InfoLevel,ReceiveBufferSize) = struct.unpack(
                        "<HH",rap.Param)
                    print("InfoLevel {} ReceiveBufferSize {}".format(
                        InfoLevel, ReceiveBufferSize) )
                    if InfoLevel == 1:
                        l = len(__shares__)
                        rout.OutParam = struct.pack("<HH", l, l)
                    rout.OutData = b""
                    comments = []
                    for i in __shares__:
                        rout.OutData += struct.pack("<13sxHHH",
                                                    i, # NetworkName
                                                    # Pad
                                                    # Type
                                                    __shares__[i][
                                                        'type'] & 0xff,
                                                    # RemarkOffsetLow
                                                    coff + len(__shares__)*20,
                                                    0x0101) # RemarkOffsetHigh
                        comments.append(__shares__[i]['comment'])
                        coff += len(__shares__[i]['comment']) + 1
                    rout.show()
                outpacket = rout
                self.outbuf = outpacket.build()
                dceplen = len(self.outbuf) + coff

                r.TotalParamCount = 8 # Status|Convert|Count|Available
                r.TotalDataCount = dceplen

                r.ParamCount = 8 # Status|Convert|Count|Available
                r.ParamOffset = 56

                r.DataCount = dceplen
                r.DataOffset = 64

                rdata.ByteCount = dceplen
                rdata.Bytes = self.outbuf + \
                    b''.join(c.encode('ascii') + b'\x00' for c in comments)


            elif TransactionName == '\\PIPE\\':
                if socket.htons(h.Setup[0]) == TRANS_NMPIPE_TRANSACT:
                    outpacket = self.process_dcerpc_packet(
                        p.getlayer(DCERPC_Header))

                    if not outpacket:
                        if self.state['stop']:
                            smblog.debug('drop dead!')
                        else:
                            smblog.error('dcerpc processing failed. bailing out.')
                        return rp
                    self.outbuf = outpacket.build()
                    dceplen = len(self.outbuf)

                    r.TotalDataCount = dceplen
                    r.DataCount = dceplen

                    rdata.ByteCount = dceplen
                    rdata.Bytes = self.outbuf

                if socket.htons(h.Setup[0]) == TRANS_NMPIPE_PEEK:
                    SetupCount = h.SetupCount
                    if SetupCount > 0:
                        smblog.info('MS17-010 - SMB RCE exploit scanning..')
                        r = SMB_Trans_Response_Simple()
                        # returned #STATUS_INSUFF_SERVER_RESOURCE as we not being patched
                        rstatus = 0xc0000205  # STATUS_INSUFF_SERVER_RESOURCES

            r /= rdata
        elif Command == SMB_COM_TRANSACTION2:
            h = p.getlayer(SMB_Trans2_Request)
            if h.Setup[0] == SMB_TRANS2_SESSION_SETUP:
                smblog.info('Possible DoublePulsar connection attempts..')
                # determine DoublePulsar opcode and command
                # https://zerosum0x0.blogspot.sg/2017/04/doublepulsar-initial-smb-backdoor-ring.html
                # The opcode list is as follows:
                # 0x23 = ping
                # 0xc8 = exec
                # 0x77 = kil
                op = calculate_doublepulsar_opcode(h.Timeout)
                op2 = hex(op)[-2:]
                oplist = [('23','ping'), ('c8','exec'), ('77','kill')]
                for fid,command in oplist:
                    if op2 == fid:
                        smblog.info("DoublePulsar request opcode: %s command: %s" % (op2, command))
                if op2 != '23' and op2 != 'c8' and op2 != '77':
                    smblog.info("unknown opcode: %s" % op2)

                # make sure the payload size not larger than 10MB
                if len(self.buf2) > 10485760:
                    self.buf2 = ''
                elif len(self.buf2) == 0 and h.DataCount == 4096:
                    self.buf2 = self.buf2 + h.Data
                elif len(self.buf2) != 0 and h.DataCount == 4096:
                    self.buf2 = self.buf2 + h.Data
                elif len(self.buf2) != 0 and h.DataCount < 4096:
                    smblog.info('DoublePulsar payload receiving..')
                    self.buf2 = self.buf2 + h.Data
                    key = bytearray([0x52, 0x73, 0x36, 0x5E])
                    xor_output = xor(self.buf2, key)
                    hash_buf2 = hashlib.md5(self.buf2);
                    smblog.info('DoublePulsar payload - MD5 (before XOR decryption): %s' % (hash_buf2.hexdigest()))
                    hash_xor_output = hashlib.md5(xor_output);
                    smblog.info('DoublePulsar payload - MD5 (after XOR decryption ): %s' % (hash_xor_output.hexdigest()))

                    # payload = some data(shellcode or code to load the executable) + executable itself
                    # try to locate the executable and remove the prepended data
                    # now, we will have the executable itself
                    offset = 0
                    for i, c in enumerate(xor_output):
                        if ((xor_output[i] == 0x4d and xor_output[i + 1] == 0x5a) and xor_output[i + 2] == 0x90):
                            offset = i
                            smblog.info('DoublePulsar payload - MZ header found...')
                            break

                    # save the captured payload/gift/evil/buddy to disk
                    smblog.info('DoublePulsar payload - Save to disk')

                    dionaea_config = g_dionaea.config().get("dionaea")
                    download_dir = dionaea_config.get("download.dir")
                    download_suffix = dionaea_config.get("download.suffix", ".tmp")

                    fp = tempfile.NamedTemporaryFile(
                        delete=False,
                        prefix="smb-",
                        suffix=download_suffix,
                        dir=download_dir
                    )
                    fp.write(xor_output[offset:])
                    fp.close()
                    self.buf2 = b''
                    xor_output = b''

                    icd = incident("dionaea.download.complete")
                    icd.path = fp.name
                    # We need the url for logging
                    icd.url = ""
                    icd.con = self
                    icd.report()
                    os.unlink(fp.name)

                r = SMB_Trans2_Response()
                rstatus = 0xc0000002  # STATUS_NOT_IMPLEMENTED
            elif h.Setup[0] == SMB_TRANS2_QUERY_FS_INFORMATION:
                r = SMB_Trans2_Final_Response()
                r.Param = SMB_Trans2_QUERY_FS_INFO_Response_Param()
                reqParam = p.getlayer(SMB_Trans2_QUERY_FS_INFORMATION_Request)
                infoLvl = reqParam.InformationLevel
                TotalAllocationUnits = smbd.max_fs_size//(self.BytesPerSector*self.SectorsPerAllocationUnit)
                freeUnits = TotalAllocationUnits - self.get_shares_size()//(self.BytesPerSector*self.SectorsPerAllocationUnit)

                if infoLvl == SMB_QUERY_FS_VOLUME_INFO:
                    info = SMB_STRUCT_QUERY_FS_VOLUME_INFO()
                    info.VolumeLabel = "DISK A"
                elif infoLvl == SMB_QUERY_FS_SIZE_INFO:
                    info = SMB_STRUCT_QUERY_FS_SIZE_INFO()
                    info.TotalAllocationUnits = TotalAllocationUnits 
                    info.TotalFreeAllocationUnits = freeUnits 
                    info.SectorsPerAllocationUnit = self.SectorsPerAllocationUnit 
                    info.BytesPerSector = self.BytesPerSector 
                elif infoLvl == SMB_QUERY_FS_DEVICE_INFO:
                    info = SMB_STRUCT_QUERY_FS_DEVICE_INFO()
                elif infoLvl == SMB_QUERY_FS_ATTRIBUTE_INFO:
                    info = SMB_STRUCT_QUERY_FS_ATTRIBUTE_INFO()
                    info.FileSystemName = self.treeConTable[reqHeader.TID]["Share"]["nativefs"]
                elif infoLvl == SMB_QUERY_FS_OBJECT_ID_INFO:
                    info = FILE_OBJECTID_BUFFER_1()
                    info.ObjectId = uuid3(NAMESPACE_OID, self.treeConTable[reqHeader.TID]["Share"]["name"]).bytes
                else:
                    info = SMB_STRUCT_QUERY_FULL_FS_SIZE_INFO()
                    info.TotalAllocationUnits = TotalAllocationUnits 
                    info.CallerFreeAllocationUnits = freeUnits 
                    info.ActualFreeAllocationUnits = freeUnits 
                    info.SectorsPerAllocationUnit = self.SectorsPerAllocationUnit 
                    info.BytesPerSector = self.BytesPerSector 
                #r.Data.append(info)
                r = r/info

            elif h.Setup[0] == SMB_TRANS2_QUERY_FILE_INFORMATION or h.Setup[0] == SMB_TRANS2_QUERY_PATH_INFORMATION:
                resp = SMB_Trans2_Final_Response()
                resp.Param = SMB_Trans2_QUERY_INFO_Response_Param()
                memFS = self.treeConTable[reqHeader.TID]["Share"]["memfs"]

                if h.Setup[0] == SMB_TRANS2_QUERY_FILE_INFORMATION:
                    reqParam = p.getlayer(SMB_Trans2_QUERY_FILE_INFO_Request)
                    if reqParam.FID in self.fileOpenTable:
                        fileName = self.fileOpenTable[reqParam.FID]["FileName"]
                    else:
                        rstatus = STATUS_INVALID_HANDLE 
                        resp = SMB_Error_Response()
                else:
                    if self.treeConTable[reqHeader.TID]["Share"]["service"] != SMB_SERVICE_DISK_SHARE:
                        rstatus = STATUS_INVALID_DEVICE_REQUEST
                        resp = SMB_Error_Response()
                    else:
                        reqParam = p.getlayer(SMB_Trans2_QUERY_PATH_INFO_Request)
                        fileName = reqParam.FileName
                        fileName = fileName.replace("\\", "/")
                        if fileName == "":
                            fileName == "/"
                        if not memFS.exists(fileName):
                            rstatus = STATUS_OBJECT_NAME_NOT_FOUND
                            resp = SMB_Error_Response()

                infoLvl = ''
                if rstatus == STATUS_SUCCESS:
                    infoLvl = reqParam.InformationLevel
                    #smblog.info('Query info for file %s' % fileName)
                    isFile = self.treeConTable[reqHeader.TID]["Share"]["service"] == SMB_SERVICE_DISK_SHARE
                    info = ""
                    if infoLvl == SMB_QUERY_FILE_ALL_INFO:
                        details = memFS.getinfo(fileName, namespaces=["details"])
                        info = SMB_STRUCT_QUERY_FILE_BASIC_INFO()
                        info.Created = details.created
                        info.LastAccess = details.accessed
                        info.LastWrite = details.modified
                        info.Change = details.modified
                        if memFS.isdir(fileName):
                            info.ExtFileAttributes = SMB_EXT_ATTR_DIRECTORY
                        else:
                            info.ExtFileAttributes = SMB_EXT_ATTR_ARCHIVE
                        resp = resp/info
                        info = SMB_STRUCT_QUERY_FILE_STANDARD_INFO()
                        info.AllocationSize = memFS.getsize(fileName) if isFile else 4096
                        info.EndOfFile = memFS.getsize(fileName) if isFile else 0
                        info.NumberOfLinks = 1
                        info.DeletePending = 0
                        info.Directory = memFS.isdir(fileName) if isFile else 0
                        resp = resp/info
                        info = SMB_STRUCT_QUERY_FILE_EA_INFO()
                        info.EaSize = 0
                        resp = resp/info
                        info = SMB_STRUCT_QUERY_FILE_NAME_INFO()
                        info.FileName = fileName.split("/")[-1]
                    elif infoLvl == SMB_QUERY_FILE_BASIC_INFO or infoLvl == 1004:
                        info = SMB_STRUCT_QUERY_FILE_BASIC_INFO()
                        if self.treeConTable[reqHeader.TID]["Share"]["service"] == SMB_SERVICE_DISK_SHARE:
                            details = memFS.getinfo(fileName, namespaces=["details"])
                            info.Created = details.created
                            info.LastAccess = details.accessed
                            info.LastWrite = details.modified
                            info.Change = details.modified
                            if memFS.isdir(fileName):
                                info.ExtFileAttributes = SMB_EXT_ATTR_DIRECTORY
                            else:
                                info.ExtFileAttributes = SMB_EXT_ATTR_ARCHIVE
                    elif infoLvl == SMB_QUERY_FILE_STANDARD_INFO or infoLvl == 1005:
                        info = SMB_STRUCT_QUERY_FILE_STANDARD_INFO()
                        if self.treeConTable[reqHeader.TID]["Share"]["service"] == SMB_SERVICE_DISK_SHARE:
                            info.AllocationSize = memFS.getsize(fileName) if isFile else 4096
                            info.EndOfFile = memFS.getsize(fileName) if isFile else 0
                            info.NumberOfLinks = 1
                            info.DeletePending = 0
                            info.Directory = memFS.isdir(fileName) if isFile else 0
                        else:
                            info.AllocationSize = 4096
                            info.EndOfFile = 0
                            info.NumberOfLinks = 1
                            info.DeletePending = 0
                            info.Directory = 0

                    elif infoLvl == SMB_QUERY_FILE_EA_INFO or infoLvl == 1007:
                        info = SMB_STRUCT_QUERY_FILE_EA_INFO()
                        info.EaSize = 0
                    elif infoLvl == SMB_QUERY_FILE_NAME_INFO or infoLvl == SMB_QUERY_FILE_ALT_NAME_INFO:
                        info = SMB_STRUCT_QUERY_FILE_NAME_INFO()
                        info.FileName = fileName.split("/")[-1]
                    elif infoLvl == SMB_QUERY_FILE_INTERNAL_INFO:
                        info = SMB_STRUCT_QUERY_FILE_INTERNAL_INFO()
                    elif infoLvl == SMB_QUERY_FILE_STREAM_INFO or infoLvl == 1022:
                        info = SMB_STRUCT_QUERY_FILE_STREAM_INFO()
                        info.StreamSize = info.StreamAllocationSize = memFS.getsize(fileName)
                        if not memFS.isdir(fileName):
                            info.StreamName = "::$DATA"
                    elif infoLvl == SMB_QUERY_FILE_NETWORK_OPEN_INFO:
                        info = SMB_STRUCT_QUERY_FILE_NETWORK_OPEN_INFO()
                        details = memFS.getinfo(fileName, namespaces=["details"])
                        info.Created = details.created
                        info.LastAccess = details.accessed
                        info.LastWrite = details.modified
                        info.Change = details.modified
                        info.AllocationSize = memFS.getsize(fileName) if isFile else 4096
                        info.EndOfFile = memFS.getsize(fileName) if isFile else 0
                        if memFS.isdir(fileName):
                            info.ExtFileAttributes = SMB_EXT_ATTR_DIRECTORY
                        else:
                            info.ExtFileAttributes = SMB_EXT_ATTR_ARCHIVE


                    resp = resp/info


                r = resp

            elif h.Setup[0] == SMB_TRANS2_SET_FILE_INFORMATION:
                resp = SMB_Trans2_Final_Response()
                #resp.Data = []
                resp.Param = SMB_Trans2_QUERY_INFO_Response_Param()
                memFS = self.treeConTable[reqHeader.TID]["Share"]["memfs"]

                if h.Setup[0] == SMB_TRANS2_SET_FILE_INFORMATION:
                    reqParam = p.getlayer(SMB_Trans2_SET_FILE_INFO_Request)
                    if reqParam.FID in self.fileOpenTable:
                        fileName = self.fileOpenTable[reqParam.FID]["FileName"]
                        fileHandle = self.fileOpenTable[reqParam.FID]["Handle"]
                    else:
                        rstatus = STATUS_INVALID_HANDLE 
                        resp = SMB_Error_Response()
                else:
                    reqParam = p.getlayer(SMB_Trans2_SET_PATH_INFO_Request)
                    fileName = reqParam.FileName.decode("utf-16le")
                    fileName = fileName.strip("\x00").strip(" ").replace("\\", "/")
                    if fileName == "":
                        fileName == "/"
                    if not memFS.exists(fileName):
                        rstatus = STATUS_OBJECT_NAME_NOT_FOUND
                        resp = SMB_Error_Response()

                infoLvl = reqParam.InformationLevel
                if rstatus == STATUS_SUCCESS:
                    if infoLvl == SMB_SET_FILE_BASIC_INFO:
                        pass
                    if infoLvl == SMB_SET_FILE_DISPOSITION_INFO or infoLvl == 1013:
                        info = p.getlayer(SMB_SET_FILE_DISPOSITION_INFO_STRUCT)
                        self.fileOpenTable[reqParam.FID]["DeletePending"] = info.DeletePending
                    if infoLvl == SMB_SET_FILE_ALLOCATION_INFO or infoLvl == 1019:
                        info = p.getlayer(SMB_SET_FILE_ALLOCATION_INFO_STRUCT)
                        inc = info.AllocationSize - memFS.getsize(fileName)
                        if inc + self.fsSize > smbd.config.memfs_limit:
                            rstatus = STATUS_INSUFF_SERVER_RESOURCES
                            res = SMB_Error_Response()
                        else:
                            fileHandle.truncate(info.AllocationSize) 
                    if infoLvl == SMB_SET_FILE_END_OF_FILE_INFO or infoLvl == 1020:
                        info = p.getlayer(SMB_SET_FILE_END_OF_FILE_INFO_STRUCT)
                        change = info.EndOfFile - memFS.getsize(fileName)
                        if change + self.fsSize > smbd.config.memfs_limit:
                            #rstatus = STATUS_DISK_FULL
                            rstatus = STATUS_INSUFF_SERVER_RESOURCES
                            resp = SMB_Error_Response()
                        else:
                            fileHandle.truncate(info.EndOfFile)


                r = resp


            elif h.Setup[0] == SMB_TRANS2_FIND_FIRST2:
                # info levels MS-CIFS p.64
                resp = SMB_Trans2_Final_Response()
                resp.Param = SMB_Trans2_FIND_FIRST2_Response_Param()
                #respData = SMB_Trans2_FIND_FIRST2_Response_Data()
                reqData = p.getlayer(SMB_Trans2_FIND_FIRST2_Request)

                # SMB_SearchAttributes to constrain the file search
                # TODO filter readonly files
                searchAttr = reqData.SearchAttributes
                excludeDirs = []
                if not searchAttr & SMB_FA_DIRECTORY:
                    excludeDirs.append("*")
                    
                #searchCount = reqData.SearchCount 
                #flags = reqData.Flags 
                info_lvl = reqData.InformationLevel
                memFS = self.treeConTable[reqHeader.TID]["Share"]["memfs"]
                fileName = reqData.FileName
                fileName = fileName.strip("\x00").strip(" ")
                fileName = fileName.replace("\\", "/")
                searchPattern = fileName.split("/")[-1]
                dirPath = fileName[:-len(searchPattern)]
                # TODO if FileName is empty return all files in the current? dir
                #smblog.info('Listing %s in %s' % (searchPattern, dirPath)) 

                searchResults = []
                try:
                    searchResults = memFS.filterdir(dirPath, files=[searchPattern], dirs=[searchPattern], exclude_dirs=excludeDirs)
                except fs.errors.ResourceNotFound:
                    rstatus = STATUS_OBJECT_PATH_NOT_FOUND


                resp.Param.SearchCount = 0

                for file in searchResults:
                    if info_lvl == SMB_FIND_FILE_BOTH_DIRECTORY_INFO:
                        info = SMB_STRUCT_FIND_FILE_BOTH_DIRECTORY_INFO()
                        info.FileName = file.name
                        fullPath = fs.path.join(dirPath, file.name)
                        details = memFS.getinfo(fullPath, namespaces=["details"])
                        info.Created = details.created
                        info.LastAccess = details.accessed
                        info.LastWrite = details.modified
                        info.Change = details.modified
                        info.EndOfFile = memFS.getsize(fullPath) 
                        info.AllocationSize = memFS.getsize(fullPath) 
                        if memFS.isdir(fullPath):
                            info.ExtFileAttributes = SMB_EXT_ATTR_DIRECTORY
                        else:
                            info.ExtFileAttributes = SMB_EXT_ATTR_ARCHIVE

                        resp = resp/info
                        resp.Param.SearchCount += 1
                    elif info_lvl == SMB_FIND_FILE_FULL_DIRECTORY_INFO:
                        info = SMB_STRUCT_FIND_FILE_FULL_DIRECTORY_INFO()
                        info.FileName = file.name
                        fullPath = fs.path.join(dirPath, file.name)
                        details = memFS.getinfo(fullPath, namespaces=["details"])
                        info.Created = details.created
                        info.LastAccess = details.accessed
                        info.LastWrite = details.modified
                        info.Change = details.modified
                        info.EndOfFile = memFS.getsize(fullPath) 
                        info.AllocationSize = memFS.getsize(fullPath) 
                        if memFS.isdir(fullPath):
                            info.ExtFileAttributes = SMB_EXT_ATTR_DIRECTORY
                        else:
                            info.ExtFileAttributes = SMB_EXT_ATTR_ARCHIVE

                        resp = resp/info
                        resp.Param.SearchCount += 1
                    elif info_lvl == SMB_FIND_FILE_NAMES_INFO:
                        info = SMB_STRUCT_FIND_FILE_NAMES_INFO()
                        info.FileName = file.name

                        resp = resp/info
                        resp.Param.SearchCount += 1
                    elif info_lvl == SMB_FIND_FILE_DIRECTORY_INFO:
                        info = SMB_STRUCT_FIND_FILE_DIRECTORY_INFO()
                        info.FileName = file.name
                        fullPath = fs.path.join(dirPath, file.name)
                        details = memFS.getinfo(fullPath, namespaces=["details"])
                        info.Created = details.created
                        info.LastAccess = details.accessed
                        info.LastWrite = details.modified
                        info.Change = details.modified
                        info.EndOfFile = memFS.getsize(fullPath) 
                        info.AllocationSize = memFS.getsize(fullPath) 
                        if memFS.isdir(fullPath):
                            info.ExtFileAttributes = SMB_EXT_ATTR_DIRECTORY
                        else:
                            info.ExtFileAttributes = SMB_EXT_ATTR_ARCHIVE

                        resp = resp/info
                        resp.Param.SearchCount += 1

                if resp.Param.SearchCount == 0:
                    rstatus = STATUS_NO_SUCH_FILE

                # TODO if InfoLevel QUERY_EAS...
                # TODO implement Search open table

                r = resp 
            else:
                r = SMB_Trans2_Response()

        elif Command == SMB_COM_DELETE:
            reqParam = p.getlayer(SMB_Delete_Request)
            resp = SMB_Delete_Response()

            memFS = self.treeConTable[reqHeader.TID]["Share"]["memfs"]
            fileName = reqParam.FileName
            fileName = fileName.strip("\x00").strip(" ")
            fileName = fileName.replace("\\", "/")
            searchPattern = fileName.split("/")[-1]
            dirPath = fileName[:-len(searchPattern)]
            if not memFS.exists(dirPath):
                rstatus = STATUS_OBJECT_PATH_SYNTAX_BAD
                #resp = SMB_Error_Response()
            else:
                #smblog.info('Delete %s in %s' % (searchPattern, dirPath)) 

                searchResults = memFS.filterdir(dirPath, files=[searchPattern], exclude_dirs=["*"])
                rstatus = STATUS_NO_SUCH_FILE
                    

                # TODO check searchAttributes if Sys or hidden files are included
                # and exclude RO
                for item in searchResults:
                    fullPath = fs.path.join(dirPath, item.name)
                    share = self.treeConTable[reqHeader.TID]["Share"]["name"]
#                    self.rwd.new_file_op(rwd.FILE_OP_DELETE, fullPath, share)
                    # TODO check if file is open somewhere
                    memFS.remove(fullPath)
                    rstatus = STATUS_SUCCESS

            r = resp

        elif Command == SMB_COM_DELETE_DIRECTORY:
            reqParam = p.getlayer(SMB_Delete_Directory_Request)
            resp = SMB_Delete_Response()

            memFS = self.treeConTable[reqHeader.TID]["Share"]["memfs"]
            dirName = reqParam.DirName
            dirName = dirName.strip("\x00").strip(" ")
            dirName = dirName.replace("\\", "/")

            try:
                memFS.removedir(dirName)
            except fs.errors.DirectoryNotEmpty:
                rstatus = STATUS_DIRECTORY_NOT_EMPTY
            except (fs.errors.DirectoryExpected, fs.errors.ResourceNotFound):
                rstatus = STATUS_OBJECT_PATH_NOT_FOUND 
            except fs.errors.RemoveRootError:
                rstatus = STATUS_CANNOT_DELETE

            #smblog.info('Delete directory %s' % (dirName)) 

                    
            r = resp

        elif Command == SMB_COM_TRANSACTION2_SECONDARY:
            h = p.getlayer(SMB_Trans2_Secondary_Request)
            r = SMB_Error_Response()
            # TODO: need some extra works
            pass
        elif Command == SMB_COM_NT_TRANSACT:
            reqParam = p.getlayer(SMB_NT_Trans_Request)
            
            resp = SMB_NT_Trans_Final_Response()
            rstatus = STATUS_NOT_SUPPORTED 
            resp.Setup = NT_TRANSACT_IOCTL
            if reqParam.Function == NT_TRANSACT_IOCTL:
                setup = SMB_NT_Trans_IOCTL_Request_Setup(reqParam.Setup)
                file_name = self.fileOpenTable[setup.FID]["FileName"]
                share_name = self.treeConTable[reqHeader.TID]["Share"]["name"]
                if setup.FunctionCode == 0x900C0:
                    file_name = file_name.split("/")[-1]
                    mac_uuid = uuid1(node=0xf64d9446bbb0).bytes
                    info = FILE_OBJECTID_BUFFER_1()
                    #info.ObjectId = mac_uuid 
                    #info.BirthObjectId = mac_uuid 
                    #info.BirthVolumeId = uuid3(NAMESPACE_OID, self.treeConTable[reqHeader.TID]["Share"]["Name"]).bytes
                    resp.Data = info.build()

                    rstatus = STATUS_INVALID_DEVICE_REQUEST 
                    resp.Setup = NT_TRANSACT_IOCTL
                    #resp.Data = mac_uuid 
                    #resp.Data += uuid3(NAMESPACE_OID, share_name).bytes
                    #resp.Data += mac_uuid 
                    #resp.Data += 16*b"\x00" 
            r = resp
        else:
            smblog.error('Not supported SMB Command: %s.' % reqHeader.Command)
            p.show()
            r = SMB_Error_Response()
            rstatus = STATUS_NOT_SUPPORTED

        if r:
            smbh.Status = rstatus
            # Deception for DoublePulsar, we fix the XOR key first as 0x5273365E
            # WannaCry will use the XOR key to encrypt and deliver next payload, so we can decode easily later
            if Command == SMB_COM_TRANSACTION2:
                h = p.getlayer(SMB_Trans2_Request)
                if h.Setup[0] == SMB_TRANS2_SESSION_SETUP:
                    smbh.MID = p.getlayer(SMB_Header).MID + 16
                    smbh.Signature = 0x000000009cf9c567
            rp = NBTSession()/smbh/r

        if Command in SMB_Commands:
            self.state['lastcmd'] = SMB_Commands[
                p.getlayer(SMB_Header).Command]
        else:
            self.state['lastcmd'] = "UNKNOWN"
        rp.show2()
        return rp

    def process_dcerpc_packet(self, buf):
        if not isinstance(buf, DCERPC_Header):
            smblog.debug("got buf, make DCERPC_Header")
            dcep = DCERPC_Header(buf)
        else:
            dcep = buf

        outbuf = None

        smblog.debug("data")
        try:
            dcep.show()
        except:
            return None
        if dcep.AuthLen > 0:
            #			print(dcep.getlayer(Raw).underlayer.load)
            #			dcep.getlayer(Raw).underlayer.decode_payload_as(DCERPC_Auth_Verfier)
            dcep.show()

        if dcep.PacketType == 11: #bind
            outbuf = DCERPC_Header()/DCERPC_Bind_Ack()
            outbuf.CallID = dcep.CallID
            c = 0
            outbuf.CtxItems = [DCERPC_Ack_CtxItem()
                               for i in range(len(dcep.CtxItems))]
            while c < len(dcep.CtxItems): #isinstance(tmp, DCERPC_CtxItem):
                tmp = dcep.CtxItems[c]
                ctxitem = outbuf.CtxItems[c]
                service_uuid = UUID(bytes_le=tmp.UUID)
                transfersyntax_uuid = UUID(bytes_le=tmp.TransferSyntax)
                ctxitem.TransferSyntax = tmp.TransferSyntax #[:16]
                ctxitem.TransferSyntaxVersion = tmp.TransferSyntaxVersion
                # possibly msf eternalblue arch64 check
                #if str(transfersyntax_uuid) == '71710533-beba-4937-8319-b5dbef9ccc36':
                #    print("eternalblue check")
                #    outbuf.AssocGroup = 0x00001b5e
                #    outbuf.SecondAddr = 135 
                #    ctxitem.AckResult = 0
                #    ctxitem.AckReason = 0

                if str(transfersyntax_uuid) == '8a885d04-1ceb-11c9-9fe8-08002b104860':
                    if service_uuid.hex in registered_services:
                        service = registered_services[service_uuid.hex]
                        smblog.info("Found a registered UUID (%s). Accepting Bind for %s" %
                                    (service_uuid , service.__class__.__name__))
                        self.state['uuid'] = service_uuid.hex
                        # Copy Transfer Syntax to CtxItem
                        ctxitem.AckResult = 0
                        ctxitem.AckReason = 0
                    else:
                        smblog.warning(
                            "Attempt to register %s failed, UUID does not exist or is not implemented",
                            service_uuid
                        )
                else:
                    smblog.warning(
                        "Attempt to register %s failed, TransferSyntax %s is unknown",
                        service_uuid,
                        transfersyntax_uuid
                    )
                i = incident("dionaea.modules.python.smb.dcerpc.bind")
                i.con = self
                i.uuid = str(service_uuid)
                i.transfersyntax = str(transfersyntax_uuid)
                i.report()
                c += 1
            outbuf.NumCtxItems = c
            outbuf.FragLen = len(outbuf.build())
            smblog.debug("dce reply")
            outbuf.show()
        elif dcep.PacketType == 0: #request
            resp = None
            if 'uuid' in self.state:
                service = registered_services[self.state['uuid']]
                resp = service.processrequest(service, self, dcep.OpNum, dcep)
                i = incident("dionaea.modules.python.smb.dcerpc.request")
                i.con = self
                i.uuid = str(UUID(bytes=bytes.fromhex(self.state['uuid'])))
                i.opnum = dcep.OpNum
                i.report()
            else:
                smblog.info("DCERPC Request without pending action")
            if not resp:
                self.state['stop'] = True
            outbuf = resp
        else:
            # unknown DCERPC packet -> logcrit and bail out.
            smblog.error('unknown DCERPC packet. bailing out.')
        return outbuf

    def handle_timeout_idle(self):
        self.smb_disc()
        return False

    def handle_disconnect(self):
        self.smb_disc()
#        for i in self.fids:
#            if self.fids[i] is not None:
#                self.fids[i].close()
#                os.unlink(self.fids[i].name)
#                del self.fids[i]
        return 0


    def smb_disc(self):
        for i in self.fileOpenTable:
            if self.fileOpenTable[i] is not None:
                if self.fileOpenTable[i]["Handle"] != -1:
                    self.fileOpenTable[i]["Handle"].close()
#        self.rwd.handle_disc()
        self.save_fs_diff()
        conCache[self.remote.host] = {}
        conCache[self.remote.host]["Shares"] = self.sharesTable
#        conCache[self.remote.host]["Detection"] = self.rwd
        conCache[self.remote.host]["DiscTime"] = datetime.datetime.now()
        smbd.active_con_count -= 1

    def save_fs_diff(self):
        mod_files = 0
        created_files = 0
        dionaea_config = g_dionaea.config().get("dionaea")
        download_dir = dionaea_config.get("download.dir")
        date = datetime.datetime.now().isoformat()
        zip_name = fs.path.join(download_dir, "fs_diff-" + self.remote.host + "-" + date + ".zip")
        diff_zip = zipfile.ZipFile(zip_name, "w")
        for share in self.sharesTable:
            memfs = self.sharesTable[share]["memfs"]
            if not memfs:
                continue
            def_memfs = smbd.config.get_share_fs(share)
            for path, dirs, files in memfs.walk():
                for f in files:
                    file_name = fs.path.join(path, f.name)
                    if def_memfs.isfile(file_name):
                        #diff_gen = diff_bytes(unified_diff, memfs.getbytes(file_name), def_memfs.getbytes(file_name)) 
                        #diff[share][file_name] = b"".join(diff_gen)
                        if memfs.getbytes(file_name) == def_memfs.getbytes(file_name): 
                            continue
                        else:
                            mod_files += 1
                    #diff[share][file_name] = memfs.getbytes(file_name) 
                    name = fs.path.join(share, file_name.strip("/"))
                    diff_zip.writestr(name, memfs.getbytes(file_name))
                    created_files += 1

        diff_zip.close()
        smblog.info("Modified files: %d Created files: %d" % (mod_files, created_files))
        print("Modified files: %d Created files: %d" % (mod_files, created_files))


    def get_shares_size(self):
        size = 0
        for share_name in self.sharesTable:
            size += get_memfs_size(self.sharesTable[share_name]["memfs"])
        return size


def get_memfs_size(memfs):
    size = 0
    for root, dirs, files in memfs.walk(namespaces=["details"]):
        size += sum(f.size for f in files)
    return size



class epmapper(smbd):
    def __init__ (self):
        connection.__init__(self,"tcp")
        smbd.__init__(self)

    def handle_io_in(self,data):
        try:
            p = DCERPC_Header(data)
        except:
            t = traceback.format_exc()
            smblog.error(t)
            return len(data)

        if len(data) < p.FragLen:
            smblog.warning("epmapper - not enough data")
            return 0

        smblog.debug("packet: %s" % p.summary())

        r = self.process_dcerpc_packet(p)

        if self.state['stop']:
            smblog.info("faint death.")
            return len(data)

        if not r or r is None:
            smblog.error('dcerpc processing failed. bailing out.')
            return len(data)

        smblog.debug("response: %s" % r.summary())
        r.show()
        self.send(r.build())

        if p.haslayer(Raw):
            smblog.warning("p.haslayer(Raw): %s" % p.getlayer(Raw).build())
            p.show()

        return len(data)


from . import rpcservices
import inspect
services = inspect.getmembers(rpcservices, inspect.isclass)
for name, servicecls in services:
    if not name == 'RPCService' and issubclass(servicecls, rpcservices.RPCService):
        register_rpc_service(servicecls())
