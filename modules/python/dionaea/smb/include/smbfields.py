#*************************************************************************
#*                               Dionaea
#*                           - catches bugs -
#*
#*
#*
#* Copyright (C) 2009  Paul Baecher & Markus Koetter & Mark Schloesser & Tan Kean Siong
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


import datetime
from uuid import UUID

from .packet import Packet, bind_bottom_up, bind_top_down
from .fieldtypes import *


#
# http://www.snia.org/tech_activities/CIFS/CIFS-TR-1p00_FINAL.pdf
#

# Capabilities
# The server supports SMB_COM_READ_ANDX_RAW and SMB_COM_WRITE_RAW (obsolescent)
CAP_RAW_MODE           = 0x0001
# The server supports SMB_COM_READ_MPX and SMB_COM_WRITE_MPX (obsolescent)
CAP_MPX_MODE           = 0x0002
CAP_UNICODE            = 0x0004 # The server supports UNICODE strings
# The server supports large files with 64 bit offsets
CAP_LARGE_FILES        = 0x0008
# The server supports the SMBs particular to the NT LM 0.12 dialect.
# Implies CAP_NT_FIND.
CAP_NT_SMBS            = 0x0010
# The server supports remote admin API requests via DCE RPC
CAP_RPC_REMOTE_APIS    = 0x0020
# The server can respond with 32 bit status codes in Status.Status
CAP_STATUS32           = 0x0040
CAP_LEVEL_II_OPLOCKS   = 0x0080 # The server supports level 2 oplocks
# The server supports the SMB,SMB_COM_LOCK_AND_READ
CAP_LOCK_AND_READ      = 0x0100
CAP_NT_FIND            = 0x0200 # Reserved
CAP_DFS                = 0x1000 # The server is DFS aware
# The server supports NT information level requests passing through
CAP_INFOLEVEL_PASSTHRU = 0x2000
# The server supports large SMB_COM_READ_ANDX (up to 64k)
CAP_LARGE_READX        = 0x4000
# The server supports large SMB_COM_WRITE_ANDX (up to 64k)
CAP_LARGE_WRITEX       = 0x8000
# The server supports CIFS Extensions for UNIX. (See Appendix D for more
# detail)
CAP_UNIX               = 0x00800000
CAP_RESERVED           = 0x02000000 # Reserved for future use
# The server supports SMB_BULK_READ, SMB_BULK_WRITE (should be 0, no known
# implementations)
CAP_BULK_TRANSFER      = 0x20000000
# The server supports compressed data transfer (BULK_TRANSFER capability
# is required to support compressed data transfer).
CAP_COMPRESSED_DATA    = 0x40000000
# The server supports extended security exchanges
CAP_EXTENDED_SECURITY  = 0x80000000

SMB_Negotiate_Capabilities = {
    CAP_RAW_MODE           :'RAW_MODE',
    CAP_MPX_MODE           :'MPX_MODE',
    CAP_UNICODE            :'UNICODE',
    CAP_LARGE_FILES        :'LARGE_FILES',
    CAP_NT_SMBS            :'NT_SMBS',
    CAP_RPC_REMOTE_APIS    :'RPC_REMOTE_APIS',
    CAP_STATUS32           :'STATUS32',
    CAP_LEVEL_II_OPLOCKS   :'LEVEL_II_OPLOCKS',
    CAP_LOCK_AND_READ      :'LOCK_AND_READ',
    CAP_NT_FIND            :'NT_FIND',
    CAP_DFS                :'DFS',
    CAP_INFOLEVEL_PASSTHRU :'INFOLEVEL_PASSTHRU',
    CAP_LARGE_READX        :'LARGE_READX',
    CAP_LARGE_WRITEX       :'LARGE_WRITEX',
    CAP_UNIX               :'UNIX',
    CAP_RESERVED           :'RESERVED',
    CAP_BULK_TRANSFER      :'BULK_TRANSFER',
    CAP_COMPRESSED_DATA    :'COMPRESSED_DATA',
    CAP_EXTENDED_SECURITY  :'EXTENDED_SECURITY',
}

# SMB_Header.Flags
# Reserved for obsolescent requests LOCK_AND_READ, WRITE_AND_CLOSE LANMAN1.0
SMB_FLAGS_LOCK_AND_READ         = (1<<0)
SMB_FLAGS_RECEIVE_BUFFER_POSTED = (1<<1) #
# When on, all pathnames in this SMB must be treated as case-less. When
# off, the pathnames are case sensitive. LANMAN1.0
SMB_FLAGS_CASES_ENSITIVITY      = (1<<3)
# Obsolescent \u2013 client case maps (canonicalizes) file and directory
# names; servers must ignore this flag. 5 Reserved for obsolescent
# requests \u2013 oplocks supported for SMB_COM_OPEN, SMB_COM_CREATE and
# SMB_COM_CREATE_NEW. Servers must ignore when processing all other SMB
# commands. LANMAN1.0
SMB_FLAGS_CANONICAL_PATHNAMES   = (1<<4)
SMB_FLAGS_OPLOCKS               = (1<<5) #
SMB_FLAGS_NOTIFY                = (1<<6) #
# When on, this SMB is being sent from the server in response to a client
# request. The Command field usually contains the same value in a protocol
# request from the client to the server as in the matching response from
# the server to the client. This bit unambiguously distinguishes the
# command request from the command response.
SMB_FLAGS_REQUEST_RESPONSE      = (1<<7)

SMB_Header_Flags = {
    SMB_FLAGS_LOCK_AND_READ         :"LOCK_AND_READ",
    SMB_FLAGS_RECEIVE_BUFFER_POSTED :"RECEIVE_BUFFER_POSTED",
    SMB_FLAGS_CASES_ENSITIVITY      :"CASES_ENSITIVITY",
    SMB_FLAGS_CANONICAL_PATHNAMES   :"CANONICAL_PATHNAMES",
    SMB_FLAGS_OPLOCKS               :"OPLOCKS",
    SMB_FLAGS_NOTIFY                :"NOTIFY",
    SMB_FLAGS_REQUEST_RESPONSE      :"REQUEST_RESPONSE",
}



# SMB_Header.Flags2
# If set in a request, the server may return long components in path names
# in the response. LM1.2X002
SMB_FLAGS2_KNOWS_LONG_NAMES    = (1<<0)
# If set, the client is aware of extended attributes (EAs).
SMB_FLAGS2_KNOWS_EAS           = (1<<1)
# If set, the SMB is integrity checked.
SMB_FLAGS2_SECURITY_SIGNATURE  = (1<<2)
SMB_FLAGS2_RESERVED1           = (1<<3)  # Reserved for future use
# If set, any path name in the request is a long name.
SMB_FLAGS2_IS_LONG_NAME        = (1<<6)
# If set, the client is aware of Extended Security negotiation. NT LM 0.12
SMB_FLAGS2_EXT_SEC             = (1<<11)
# If set, any request pathnames in this SMB should be resolved in the
# Distributed File System. NT LM 0.12
SMB_FLAGS2_DFS                 = (1<<12)
# If set, indicates that a read will be permitted if the client does not
# have read permission but does have execute permission. This flag is only
# useful on a read request.
SMB_FLAGS2_PAGING_IO           = (1<<13)
# If set, specifies that the returned error code is a 32 bit error code in
# Status.Status. Otherwise the Status.DosError.ErrorClass and
# Status.DosError.Error fields contain the DOS-style error information.
# When passing NT status codes is negotiated, this flag should be set for
# every SMB. NT LM 0.12
SMB_FLAGS2_ERR_STATUS          = (1<<14)
# If set, any fields of datatype STRING in this SMB message are encoded as
# UNICODE. Otherwise, they are in ASCII. The character encoding for
# Unicode fields SHOULD be UTF-16 (little endian). NT LM 0.12
SMB_FLAGS2_UNICODE             = (1<<15)

SMB_Header_Flags2 = {
    SMB_FLAGS2_KNOWS_LONG_NAMES    :'KNOWS_LONG_NAMES',
    SMB_FLAGS2_KNOWS_EAS           :'KNOWS_EAS',
    SMB_FLAGS2_SECURITY_SIGNATURE  :'SECURITY_SIGNATURE',
    SMB_FLAGS2_RESERVED1           :'RESERVED1',
    SMB_FLAGS2_IS_LONG_NAME        :'IS_LONG_NAME',
    SMB_FLAGS2_EXT_SEC             :'EXT_SEC',
    SMB_FLAGS2_DFS                 :'DFS',
    SMB_FLAGS2_PAGING_IO           :'PAGING_IO',
    SMB_FLAGS2_ERR_STATUS          :'ERR_STATUS',
    SMB_FLAGS2_UNICODE             :'UNICODE',
}

# Service types MS-CIFS p. 297
SMB_SERVICE_DISK_SHARE          = "A:"
SMB_SERVICE_PRINT_SHARE         = "LTP1:"
SMB_SERVICE_NAMED_PIPE          = "IPC"
SMB_SERVICE_COMM_DEVICE         = "COMM"
SMB_SERVICE_ANY                 = "?????"

# Resource types MS-CIFS p.350
SMB_RES_DISK            = 0x0000
SMB_RES_BYTE_MODE_PIPE  = 0x0001
SMB_RES_MSG_MODE_PIPE   = 0x0002
SMB_RES_PRINTER         = 0x0003
SMB_RES_COMM_DEV        = 0x0004

SMB_ResourceTypes = {
        SMB_RES_DISK            : "FILE_TYPE_DISK",      
        SMB_RES_BYTE_MODE_PIPE  : "FILE_TYPE_BYTE_MODE_PIPE",
        SMB_RES_MSG_MODE_PIPE   : "FILE_TYPE_MESSAGE_MODE_PIPE",
        SMB_RES_PRINTER         : "FILE_TYPE_PRINTER",
        SMB_RES_COMM_DEV        : "FILE_TYPE_COMM_DEVICE"
}
# SMB_Header.Command
SMB_COM_CREATE_DIRECTORY       = 0x00
SMB_COM_DELETE_DIRECTORY       = 0x01
SMB_COM_OPEN                   = 0x02
SMB_COM_CREATE                 = 0x03
SMB_COM_CLOSE                  = 0x04
SMB_COM_FLUSH                  = 0x05
SMB_COM_DELETE                 = 0x06
SMB_COM_RENAME                 = 0x07
SMB_COM_QUERY_INFORMATION      = 0x08
SMB_COM_SET_INFORMATION        = 0x09
SMB_COM_READ                   = 0x0A
SMB_COM_WRITE                  = 0x0B
SMB_COM_LOCK_BYTE_RANGE        = 0x0C
SMB_COM_UNLOCK_BYTE_RANGE      = 0x0D
SMB_COM_CREATE_TEMPORARY       = 0x0E
SMB_COM_CREATE_NEW             = 0x0F
SMB_COM_CHECK_DIRECTORY        = 0x10
SMB_COM_PROCESS_EXIT           = 0x11
SMB_COM_SEEK                   = 0x12
SMB_COM_LOCK_AND_READ          = 0x13
SMB_COM_WRITE_AND_UNLOCK       = 0x14
SMB_COM_READ_RAW               = 0x1A
SMB_COM_READ_MPX               = 0x1B
SMB_COM_READ_MPX_SECONDARY     = 0x1C
SMB_COM_WRITE_RAW              = 0x1D
SMB_COM_WRITE_MPX              = 0x1E
SMB_COM_WRITE_MPX_SECONDARY    = 0x1F
SMB_COM_WRITE_COMPLETE         = 0x20
SMB_COM_QUERY_SERVER           = 0x21
SMB_COM_SET_INFORMATION2       = 0x22
SMB_COM_QUERY_INFORMATION2     = 0x23
SMB_COM_LOCKING_ANDX           = 0x24
SMB_COM_TRANSACTION            = 0x25
SMB_COM_TRANSACTION_SECONDARY  = 0x26
SMB_COM_IOCTL                  = 0x27
SMB_COM_IOCTL_SECONDARY        = 0x28
SMB_COM_COPY                   = 0x29
SMB_COM_MOVE                   = 0x2A
SMB_COM_ECHO                   = 0x2B
SMB_COM_WRITE_AND_CLOSE        = 0x2C
SMB_COM_OPEN_ANDX              = 0x2D
SMB_COM_READ_ANDX              = 0x2E
SMB_COM_WRITE_ANDX             = 0x2F
SMB_COM_NEW_FILE_SIZE          = 0x30
SMB_COM_CLOSE_AND_TREE_DISC    = 0x31
SMB_COM_TRANSACTION2           = 0x32
SMB_COM_TRANSACTION2_SECONDARY = 0x33
SMB_COM_FIND_CLOSE2            = 0x34
SMB_COM_FIND_NOTIFY_CLOSE      = 0x35
SMB_COM_TREE_CONNECT           = 0x70
SMB_COM_TREE_DISCONNECT        = 0x71
SMB_COM_NEGOTIATE              = 0x72
SMB_COM_SESSION_SETUP_ANDX     = 0x73
SMB_COM_LOGOFF_ANDX            = 0x74
SMB_COM_TREE_CONNECT_ANDX      = 0x75
SMB_COM_QUERY_INFORMATION_DISK = 0x80
SMB_COM_SEARCH                 = 0x81
SMB_COM_FIND                   = 0x82
SMB_COM_FIND_UNIQUE            = 0x83
SMB_COM_FIND_CLOSE             = 0x84
SMB_COM_NT_TRANSACT            = 0xA0
SMB_COM_NT_TRANSACT_SECONDARY  = 0xA1
SMB_COM_NT_CREATE_ANDX         = 0xA2
SMB_COM_NT_CANCEL              = 0xA4
SMB_COM_NT_RENAME              = 0xA5
SMB_COM_OPEN_PRINT_FILE        = 0xC0
SMB_COM_WRITE_PRINT_FILE       = 0xC1
SMB_COM_CLOSE_PRINT_FILE       = 0xC2
SMB_COM_GET_PRINT_QUEUE        = 0xC3
SMB_COM_READ_BULK              = 0xD8
SMB_COM_WRITE_BULK             = 0xD9
SMB_COM_WRITE_BULK_DATA        = 0xDA
SMB_COM_NONE                   = 0xFF

SMB_Commands = {
    SMB_COM_CREATE_DIRECTORY       :"SMB_COM_CREATE_DIRECTORY",
    SMB_COM_DELETE_DIRECTORY       :"SMB_COM_DELETE_DIRECTORY",
    SMB_COM_OPEN                   :"SMB_COM_OPEN",
    SMB_COM_CREATE                 :"SMB_COM_CREATE",
    SMB_COM_CLOSE                  :"SMB_COM_CLOSE",
    SMB_COM_FLUSH                  :"SMB_COM_FLUSH",
    SMB_COM_DELETE                 :"SMB_COM_DELETE",
    SMB_COM_RENAME                 :"SMB_COM_RENAME",
    SMB_COM_QUERY_INFORMATION      :"SMB_COM_QUERY_INFORMATION",
    SMB_COM_SET_INFORMATION        :"SMB_COM_SET_INFORMATION",
    SMB_COM_READ                   :"SMB_COM_READ",
    SMB_COM_WRITE                  :"SMB_COM_WRITE",
    SMB_COM_LOCK_BYTE_RANGE        :"SMB_COM_LOCK_BYTE_RANGE",
    SMB_COM_UNLOCK_BYTE_RANGE      :"SMB_COM_UNLOCK_BYTE_RANGE",
    SMB_COM_CREATE_TEMPORARY       :"SMB_COM_CREATE_TEMPORARY",
    SMB_COM_CREATE_NEW             :"SMB_COM_CREATE_NEW",
    SMB_COM_CHECK_DIRECTORY        :"SMB_COM_CHECK_DIRECTORY",
    SMB_COM_PROCESS_EXIT           :"SMB_COM_PROCESS_EXIT",
    SMB_COM_SEEK                   :"SMB_COM_SEEK",
    SMB_COM_LOCK_AND_READ          :"SMB_COM_LOCK_AND_READ",
    SMB_COM_WRITE_AND_UNLOCK       :"SMB_COM_WRITE_AND_UNLOCK",
    SMB_COM_READ_RAW               :"SMB_COM_READ_RAW",
    SMB_COM_READ_MPX               :"SMB_COM_READ_MPX",
    SMB_COM_READ_MPX_SECONDARY     :"SMB_COM_READ_MPX_SECONDARY",
    SMB_COM_WRITE_RAW              :"SMB_COM_WRITE_RAW",
    SMB_COM_WRITE_MPX              :"SMB_COM_WRITE_MPX",
    SMB_COM_WRITE_MPX_SECONDARY    :"SMB_COM_WRITE_MPX_SECONDARY",
    SMB_COM_WRITE_COMPLETE         :"SMB_COM_WRITE_COMPLETE",
    SMB_COM_QUERY_SERVER           :"SMB_COM_QUERY_SERVER",
    SMB_COM_SET_INFORMATION2       :"SMB_COM_SET_INFORMATION2",
    SMB_COM_QUERY_INFORMATION2     :"SMB_COM_QUERY_INFORMATION2",
    SMB_COM_LOCKING_ANDX           :"SMB_COM_LOCKING_ANDX",
    SMB_COM_TRANSACTION            :"SMB_COM_TRANSACTION",
    SMB_COM_TRANSACTION_SECONDARY  :"SMB_COM_TRANSACTION_SECONDARY",
    SMB_COM_IOCTL                  :"SMB_COM_IOCTL",
    SMB_COM_IOCTL_SECONDARY        :"SMB_COM_IOCTL_SECONDARY",
    SMB_COM_COPY                   :"SMB_COM_COPY",
    SMB_COM_MOVE                   :"SMB_COM_MOVE",
    SMB_COM_ECHO                   :"SMB_COM_ECHO",
    SMB_COM_WRITE_AND_CLOSE        :"SMB_COM_WRITE_AND_CLOSE",
    SMB_COM_OPEN_ANDX              :"SMB_COM_OPEN_ANDX",
    SMB_COM_READ_ANDX              :"SMB_COM_READ_ANDX",
    SMB_COM_WRITE_ANDX             :"SMB_COM_WRITE_ANDX",
    SMB_COM_NEW_FILE_SIZE          :"SMB_COM_NEW_FILE_SIZE",
    SMB_COM_CLOSE_AND_TREE_DISC    :"SMB_COM_CLOSE_AND_TREE_DISC",
    SMB_COM_TRANSACTION2           :"SMB_COM_TRANSACTION2",
    SMB_COM_TRANSACTION2_SECONDARY :"SMB_COM_TRANSACTION2_SECONDARY",
    SMB_COM_FIND_CLOSE2            :"SMB_COM_FIND_CLOSE2",
    SMB_COM_FIND_NOTIFY_CLOSE      :"SMB_COM_FIND_NOTIFY_CLOSE",
    SMB_COM_TREE_CONNECT           :"SMB_COM_TREE_CONNECT",
    SMB_COM_TREE_DISCONNECT        :"SMB_COM_TREE_DISCONNECT",
    SMB_COM_NEGOTIATE              :"SMB_COM_NEGOTIATE",
    SMB_COM_SESSION_SETUP_ANDX     :"SMB_COM_SESSION_SETUP_ANDX",
    SMB_COM_LOGOFF_ANDX            :"SMB_COM_LOGOFF_ANDX",
    SMB_COM_TREE_CONNECT_ANDX      :"SMB_COM_TREE_CONNECT_ANDX",
    SMB_COM_QUERY_INFORMATION_DISK :"SMB_COM_QUERY_INFORMATION_DISK",
    SMB_COM_SEARCH                 :"SMB_COM_SEARCH",
    SMB_COM_FIND                   :"SMB_COM_FIND",
    SMB_COM_FIND_UNIQUE            :"SMB_COM_FIND_UNIQUE",
    SMB_COM_FIND_CLOSE             :"SMB_COM_FIND_CLOSE",
    SMB_COM_NT_TRANSACT            :"SMB_COM_NT_TRANSACT",
    SMB_COM_NT_TRANSACT_SECONDARY  :"SMB_COM_NT_TRANSACT_SECONDARY",
    SMB_COM_NT_CREATE_ANDX         :"SMB_COM_NT_CREATE_ANDX",
    SMB_COM_NT_CANCEL              :"SMB_COM_NT_CANCEL",
    SMB_COM_NT_RENAME              :"SMB_COM_NT_RENAME",
    SMB_COM_OPEN_PRINT_FILE        :"SMB_COM_OPEN_PRINT_FILE",
    SMB_COM_WRITE_PRINT_FILE       :"SMB_COM_WRITE_PRINT_FILE",
    SMB_COM_CLOSE_PRINT_FILE       :"SMB_COM_CLOSE_PRINT_FILE",
    SMB_COM_GET_PRINT_QUEUE        :"SMB_COM_GET_PRINT_QUEUE",
    SMB_COM_READ_BULK              :"SMB_COM_READ_BULK",
    SMB_COM_WRITE_BULK             :"SMB_COM_WRITE_BULK",
    SMB_COM_WRITE_BULK_DATA        :"SMB_COM_WRITE_BULK_DATA",
    SMB_COM_NONE                   :"SMB_COM_NONE",
}


# Create file with extended attributes
SMB_TRANS2_OPEN2                    = 0x00
SMB_TRANS2_FIND_FIRST2              = 0x01 # Begin search for files
SMB_TRANS2_FIND_NEXT2               = 0x02 # Resume search for files
SMB_TRANS2_QUERY_FS_INFORMATION     = 0x03 # Get file system information
SMB_TRANS_SET_FS_INFORMATION        = 0x04 # Reserved (?)
# Get information about a named file or directory
SMB_TRANS2_QUERY_PATH_INFORMATION   = 0x05
# Set information about a named file or directory
SMB_TRANS2_SET_PATH_INFORMATION     = 0x06
SMB_TRANS2_QUERY_FILE_INFORMATION   = 0x07 # Get information about a handle
SMB_TRANS2_SET_FILE_INFORMATION     = 0x08 # Set information by handle
SMB_TRANS2_FSCTL                    = 0x09 # Not implemented by NT server
SMB_TRANS2_IOCTL2                   = 0x0A # Not implemented by NT server
SMB_TRANS2_FIND_NOTIFY_FIRST        = 0x0B # Not implemented by NT server
SMB_TRANS2_FIND_NOTIFY_NEXT         = 0x0C # Not implemented by NT server
# Create directory with extended attributes
SMB_TRANS2_CREATE_DIRECTORY         = 0x0D
# Session setup with extended security information
SMB_TRANS2_SESSION_SETUP            = 0x0E


SMB_Trans2_Commands = {
    SMB_TRANS2_OPEN2                    :"TRANS2_OPEN2",
    SMB_TRANS2_FIND_FIRST2              :"TRANS2_FIND_FIRST2",
    SMB_TRANS2_FIND_NEXT2               :"TRANS2_FIND_NEXT2",
    SMB_TRANS2_QUERY_FS_INFORMATION     :"TRANS2_QUERY_FS_INFORMATION",
    SMB_TRANS_SET_FS_INFORMATION        :"TRANS2_SET_FS_INFORMATION",
    SMB_TRANS2_QUERY_PATH_INFORMATION   :"TRANS2_QUERY_PATH_INFORMATION",
    SMB_TRANS2_SET_PATH_INFORMATION     :"TRANS2_SET_PATH_INFORMATION",
    SMB_TRANS2_QUERY_FILE_INFORMATION   :"TRANS2_QUERY_FILE_INFORMATION",
    SMB_TRANS2_SET_FILE_INFORMATION     :"TRANS2_SET_FILE_INFORMATION",
    SMB_TRANS2_FSCTL                    :"TRANS2_FSCTL",
    SMB_TRANS2_IOCTL2                   :"TRANS2_IOCTL2",
    SMB_TRANS2_FIND_NOTIFY_FIRST        :"TRANS2_FIND_NOTIFY_FIRST",
    SMB_TRANS2_FIND_NOTIFY_NEXT         :"TRANS2_FIND_NOTIFY_NEXT",
    SMB_TRANS2_CREATE_DIRECTORY         :"TRANS2_CREATE_DIRECTORY",
    SMB_TRANS2_SESSION_SETUP            :"TRANS2_SESSION_SETUP",
}
# Trans2 QUERY Information level MS-CIFS p.65
SMB_INFO_STANDARD                 = 0x0001
SMB_INFO_QUERY_EA_SIZE            = 0x0002
SMB_INFO_QUERY_EAS_FROM_LIST      = 0x0003
SMB_INFO_QUERY_ALL_EAS            = 0x0004
SMB_INFO_IS_NAME_VALID            = 0x0006
SMB_QUERY_FILE_BASIC_INFO         = 0x0101
SMB_QUERY_FILE_STANDARD_INFO      = 0x0102
SMB_QUERY_FILE_EA_INFO            = 0x0103
SMB_QUERY_FILE_NAME_INFO          = 0x0104
SMB_QUERY_FILE_ALL_INFO           = 0x0107
SMB_QUERY_FILE_ALT_NAME_INFO      = 0x0108
SMB_QUERY_FILE_STREAM_INFO        = 0x0109
SMB_QUERY_FILE_COMPRESSION_INFO   = 0x010b
SMB_QUERY_FILE_INTERNAL_INFO      = 1006

SMB_QueryInfoLvl = {
    SMB_INFO_STANDARD                 : 0x0001,
    SMB_INFO_QUERY_EA_SIZE            : 0x0002,
    SMB_INFO_QUERY_EAS_FROM_LIST      : 0x0003,
    SMB_INFO_QUERY_ALL_EAS            : 0x0004,
    SMB_INFO_IS_NAME_VALID            : 0x0006,
    SMB_QUERY_FILE_BASIC_INFO         : 0x0101,
    SMB_QUERY_FILE_STANDARD_INFO      : 0x0102,
    SMB_QUERY_FILE_EA_INFO            : 0x0103,
    SMB_QUERY_FILE_NAME_INFO          : 0x0104,
    SMB_QUERY_FILE_ALL_INFO           : 0x0107,
    SMB_QUERY_FILE_ALT_NAME_INFO      : 0x0108,
    SMB_QUERY_FILE_STREAM_INFO        : 0x0109,
    SMB_QUERY_FILE_COMPRESSION_INFO   : 0x010b,
    SMB_QUERY_FILE_INTERNAL_INFO      : 0x1006
}

# Trans2 QUERY_FS infomation level codes MS-CIFS p.65
SMB_INFO_ALLOCATION                 = 0x0001
SMB_INFO_VOLUME                     = 0x0002
SMB_QUERY_FS_VOLUME_INFO            = 0x0102
SMB_QUERY_FS_SIZE_INFO              = 0x0103
SMB_QUERY_FS_DEVICE_INFO            = 0x0104
SMB_QUERY_FS_ATTRIBUTE_INFO         = 0x0105

SMB_QueryFSInfoLvl = { 
    SMB_INFO_ALLOCATION         : "SMB_INFO_ALLOCATION",               
    SMB_INFO_VOLUME             : "SMB_INFO_VOLUME",
    SMB_QUERY_FS_VOLUME_INFO    : "SMB_QUERY_FS_VOLUME_INFO",
    SMB_QUERY_FS_SIZE_INFO      : "SMB_QUERY_FS_SIZE_INFO",
    SMB_QUERY_FS_DEVICE_INFO    : "SMB_QUERY_FS_DEVICE_INFO",
    SMB_QUERY_FS_ATTRIBUTE_INFO : "SMB_QUERY_FS_ATTRIBUTE_INFO"
}

# TRANS2 FIND Information Level Codes MS-CIFS p.64
SMB_INFO_STANDARD                   = 0x0001
SMB_INFO_QUERY_EA_SIZE              = 0x0002
SMB_INFO_QUERY_EAS_FROM_LIST        = 0x0003
SMB_FIND_FILE_DIRECTORY_INFO        = 0x0101
SMB_FIND_FILE_FULL_DIRECTORY_INFO   = 0x0102
SMB_FIND_FILE_NAMES_INFO            = 0x0103
SMB_FIND_FILE_BOTH_DIRECTORY_INFO   = 0x0104

SMB_Trans2_FIND_Info_Level = {
    SMB_INFO_STANDARD                   :"SMB_INFO_STANDARD",
    SMB_INFO_QUERY_EA_SIZE              :"SMB_INFO_QUERY_EA_SIZE",
    SMB_INFO_QUERY_EAS_FROM_LIST        :"SMB_INFO_QUERY_EA_SIZE",
    SMB_FIND_FILE_DIRECTORY_INFO        :"SMB_FIND_FILE_DIRECTORY_INFO",     
    SMB_FIND_FILE_FULL_DIRECTORY_INFO   :"SMB_FIND_FILE_FULL_DIRECTORY_INFO",
    SMB_FIND_FILE_NAMES_INFO            :"SMB_FIND_FILE_NAMES_INFO",
    SMB_FIND_FILE_BOTH_DIRECTORY_INFO   :"SMB_FIND_FILE_BOTH_DIRECTORY_INFO",
}


# Trans2 FIND_FIRST2 flags
SMB_FIND_CLOSE_AFTER_REQUEST     = 0x0001
SMB_FIND_CLOSE_AT_EOS            = 0x0002
SMB_FIND_RETURN_RESUME_KEYS      = 0x0004
SMB_FIND_CONTINUE_FROM_LAST      = 0x0008
SMB_FIND_WITH_BACKUP_INTENT      = 0x0010

SMB_Trans2_FIND_FIRST2_Flags = {
    SMB_FIND_CLOSE_AFTER_REQUEST     :"SMB_FIND_CLOSE_AFTER_REQUEST",
    SMB_FIND_CLOSE_AT_EOS            :"SMB_FIND_CLOSE_AT_EOS",
    SMB_FIND_RETURN_RESUME_KEYS      :"SMB_FIND_RETURN_RESUME_KEYS",
    SMB_FIND_CONTINUE_FROM_LAST      :"SMB_FIND_CONTINUE_FROM_LAST",
    SMB_FIND_WITH_BACKUP_INTENT      :"SMB_FIND_WITH_BACKUP_INTENT",
}

# SMB Extended File Attributes MS-CIFS p.46
SMB_EXT_ATTR_READONLY           = 0x00000001
SMB_EXT_ATTR_HIDDEN             = 0x00000002
SMB_EXT_ATTR_SYSTEM             = 0x00000004
SMB_EXT_ATTR_DIRECTORY          = 0x00000010
SMB_EXT_ATTR_ARCHIVE            = 0x00000020
SMB_EXT_ATTR_NORMAL             = 0x00000080
SMB_EXT_ATTR_TEMPORARY          = 0x00000100
SMB_EXT_ATTR_COMPRESSED         = 0x00000800

SMB_ExtFileAttributes = {
    SMB_EXT_ATTR_READONLY       : "READONLY",
    SMB_EXT_ATTR_HIDDEN         : "HIDDEN",      
    SMB_EXT_ATTR_SYSTEM         : "SYSTEM",
    SMB_EXT_ATTR_DIRECTORY      : "DIRECTORY",
    SMB_EXT_ATTR_ARCHIVE        : "ARCHIVE",
    SMB_EXT_ATTR_NORMAL         : "NORMAL",
    SMB_EXT_ATTR_TEMPORARY      : "TEMPORARY",
    SMB_EXT_ATTR_COMPRESSED     : "COMPRESSED",
}






DCERPC_PacketTypes = {
    11:"Bind",
    12:"Bind Ack",
    0:"Request",
}

# NT Create AndX Flags
# page 76

SMB_CF_NONE             = 0x00
SMB_CF_REQ_OPLOCK       = 0x02 # Request an oplock
SMB_CF_REQ_BATCH_OPLOCK = 0x04 # Request a batch oplock
SMB_CF_TARGET_DIRECTORY = 0x08 # Target of open must be directory

SMB_CreateFlags = {
    SMB_CF_NONE             :'NONE',
    SMB_CF_REQ_OPLOCK       :'REQ_OPLOCK',
    SMB_CF_REQ_BATCH_OPLOCK :'REQ_BATCH_OPLOCK',
    SMB_CF_TARGET_DIRECTORY :'TARGET_DIRECTORY',
}

# File Search Attributes (Trans2 FIND FIRST2)
SMB_SA_READONLY     = 0x0100 
SMB_SA_HIDDEN       = 0x0200 
SMB_SA_SYSTEM       = 0x0400 
SMB_SA_DIRECTORY    = 0x1000 
SMB_SA_ARCHIVE      = 0x2000 

SMB_SearchAttributes = {
    SMB_SA_READONLY     : "READONLY", 
    SMB_SA_HIDDEN       : "HIDDEN", 
    SMB_SA_SYSTEM       : "SYSTEM",
    SMB_SA_DIRECTORY    : "DIRECTORY",
    SMB_SA_ARCHIVE      : "ARCHIVE",
}



# File Attribute Encoding
SMB_FA_READONLY   = 0x0001 # Read only file
SMB_FA_HIDDEN     = 0x0002 # Hidden file
SMB_FA_SYSTEM     = 0x0004 # System file
SMB_FA_VOLUME     = 0x0008 # Volume

SMB_FA_DIRECTORY  = 0x0010 # Directory
SMB_FA_ARCHIVE    = 0x0020 # Archive file
SMB_FA_DEVICE     = 0x0040 # Device
SMB_FA_NORMAL     = 0x0080 # Normal

SMB_FA_TEMP       = 0x0100 # Temporary
SMB_FA_SPARSE     = 0x0200 # Sparse
SMB_FA_REPARSE    = 0x0400 # Reparse
SMB_FA_COMPRESS   = 0x0800 # Compressed

SMB_FA_OFFLINE    = 0x1000 # Offline
SMB_FA_INDEX      = 0x2000 # Indexed
SMB_FA_ENCRYPTED  = 0x4000 # Encrypted

SMB_FileAttributes = {
    SMB_FA_READONLY  : "READONLY",
    SMB_FA_HIDDEN    : "HIDDEN",
    SMB_FA_SYSTEM    : "SYSTEM",
    SMB_FA_VOLUME    : "VOLUME",

    SMB_FA_DIRECTORY : "DIRECTORY",
    SMB_FA_ARCHIVE   : "ARCHIVE",
    SMB_FA_DEVICE    : "DEVICE",
    SMB_FA_NORMAL    : "NORMAL",

    SMB_FA_TEMP      : "TEMP",
    SMB_FA_SPARSE    : "SPARSE",
    SMB_FA_REPARSE   : "REPARSE",
    SMB_FA_COMPRESS  : "COMPRESS",

    SMB_FA_OFFLINE   : "OFFLINE",
    SMB_FA_INDEX     : "INDEX",
    SMB_FA_ENCRYPTED : "ENCRYPTED",
}

# Share Access
SMB_FILE_NO_SHARE    = 0x00000000 # Prevents the file from being shared.
# Other open operations can be performed on the file for read access.
SMB_FILE_SHARE_READ  = 0x00000001
# Other open operations can be performed on the file for write access.
SMB_FILE_SHARE_WRITE = 0x00000002
# Other open operations can be performed on the file for delete access.
SMB_FILE_SHARE_DELETE = 0x00000004


SMB_ShareAccess = {
    SMB_FILE_NO_SHARE     :"NO_SHARE",
    SMB_FILE_SHARE_READ   :"READ",
    SMB_FILE_SHARE_WRITE  :"WRITE",
    SMB_FILE_SHARE_DELETE :"DELETE"
}

# CreateDispositions 
# have different meaning in response MS-CIFS p.349
SMB_CREATDISP_FILE_SUPERSEDE        = 0x00000000
SMB_CREATDISP_FILE_OPEN             = 0x00000001
SMB_CREATDISP_FILE_CREATE           = 0x00000002
# in resp: file has been overwritten
SMB_CREATDISP_FILE_OPEN_IF          = 0x00000003
# in resp: file already exists
SMB_CREATDISP_FILE_OVERWRITE        = 0x00000004
# in resp: file does not exist
SMB_CREATDISP_FILE_OVERWRITE_IF     = 0x00000005

SMB_CreateDispositions = {
    SMB_CREATDISP_FILE_SUPERSEDE    : "FILE_SUPERSEDE",
    SMB_CREATDISP_FILE_OPEN         : "FILE_OPEN",
    SMB_CREATDISP_FILE_CREATE       : "FILE_CREATE",
    SMB_CREATDISP_FILE_OPEN_IF      : "FILE_OPEN_IF",
    SMB_CREATDISP_FILE_OVERWRITE    : "FILE_OVERWRITE",
    SMB_CREATDISP_FILE_OVERWRITE_IF : "FILE_OVERWRITE_IF"
}


# CreateOptions
SMB_CREATOPT_NONE                   =(0)
SMB_CREATOPT_DIRECTORY              =(1<<0)
SMB_CREATOPT_WRITETHROUGH           =(1<<1)
SMB_CREATOPT_SEQONLY                =(1<<2)
SMB_CREATOPT_INTERMBUF              =(1<<3)
SMB_CREATOPT_SYNCIOALERT            =(1<<4)
SMB_CREATOPT_SYNCIONOALERT          =(1<<5)
SMB_CREATOPT_NONDIRECTORY           =(1<<6)
SMB_CREATOPT_CREATETREECONN         =(1<<7)
SMB_CREATOPT_COMPLETEIFOPLOCK       =(1<<8)
SMB_CREATOPT_NOEAKNOWLEDGE          =(1<<9)
SMB_CREATOPT_LONG_FILENAMES         =(1<<10)
SMB_CREATOPT_RANDOMACCESS           =(1<<11)
SMB_CREATOPT_DELETE_ON_CLOSE        =(1<<12)
SMB_CREATOPT_OPEN_BY_ID             =(1<<13)
SMB_CREATOPT_BACKUP_INTENT          =(1<<14)
SMB_CREATOPT_NOCOMPRESSION          =(1<<15)
SMB_CREATOPT_RESERVE_OPFILTER       =(1<<20)
SMB_CREATOPT_OPEN_REPARSE_POINT     =(1<<21)
SMB_CREATOPT_OPEN_NO_RECALL         =(1<<22)
SMB_CREATOPT_OPEN_FOR_SPACE_QUERY   =(1<<23)

SMB_CreateOptions = {
    SMB_CREATOPT_NONE                   :"NONE",
    SMB_CREATOPT_DIRECTORY              :"DIRECTORY",
    SMB_CREATOPT_WRITETHROUGH           :"WRITETHROUGH",
    SMB_CREATOPT_SEQONLY                :"SEQONLY",
    SMB_CREATOPT_INTERMBUF              :"INTERMBUF",
    SMB_CREATOPT_SYNCIOALERT            :"SYNCIOALERT",
    SMB_CREATOPT_SYNCIONOALERT          :"SYNCIONOALERT",
    SMB_CREATOPT_NONDIRECTORY           :"NONDIRECTORY",
    SMB_CREATOPT_CREATETREECONN         :"CREATETREECONN",
    SMB_CREATOPT_COMPLETEIFOPLOCK       :"COMPLETEIFOPLOCK",
    SMB_CREATOPT_NOEAKNOWLEDGE          :"NOEAKNOWLEDGE",
    SMB_CREATOPT_LONG_FILENAMES         :"LONG_FILENAMES",
    SMB_CREATOPT_RANDOMACCESS           :"RANDOMACCESS",
    SMB_CREATOPT_DELETE_ON_CLOSE        :"DELETE_ON_CLOSE",
    SMB_CREATOPT_OPEN_BY_ID             :"OPEN_BY_ID",
    SMB_CREATOPT_BACKUP_INTENT          :"BACKUP_INTENT",
    SMB_CREATOPT_NOCOMPRESSION          :"NOCOMPRESSION",
    SMB_CREATOPT_RESERVE_OPFILTER       :"RESERVE_OPFILTER",
    SMB_CREATOPT_OPEN_REPARSE_POINT     :"OPEN_REPARSE_POINT",
    SMB_CREATOPT_OPEN_NO_RECALL         :"OPEN_NO_RECALL",
    SMB_CREATOPT_OPEN_FOR_SPACE_QUERY   :"OPEN_FOR_SPACE_QUERY",
}

# CreateFlags
SMB_CREATEFL_NONE                = (0)
SMB_CREATEFL_EXCL_OPLOCK         = (1<<1)
SMB_CREATEFL_BATCH_OPLOCK        = (1<<2)
SMB_CREATEFL_CREATE_DIRECTORY    = (1<<3)
SMB_CREATEFL_EXT_RESP            = (1<<4)

SMB_CreateFlags = {
    SMB_CREATEFL_NONE             : "NONE",
    SMB_CREATEFL_EXCL_OPLOCK      : "EXCL_OPLOCK",
    SMB_CREATEFL_BATCH_OPLOCK     : "BATCH_OPLOCK",
    SMB_CREATEFL_CREATE_DIRECTORY : "CREATE_DIRECTORY",
    SMB_CREATEFL_EXT_RESP         : "EXT_RESP",
}

# Access Mask Flags
SMB_AM_NONE             = (0)
SMB_AM_READ             = (1<<0)
SMB_AM_WRITE            = (1<<1)
SMB_AM_APPEND           = (1<<2)
SMB_AM_READ_EA          = (1<<3)
SMB_AM_WRITE_EA         = (1<<4)
SMB_AM_EXECUTE          = (1<<5)
SMB_AM_DELETE_CHILD     = (1<<6)
SMB_AM_READ_ATTR        = (1<<7)
SMB_AM_WRITE_ATTR       = (1<<8)
SMB_AM_DELETE           = (1<<16)
SMB_AM_READ_CTRL        = (1<<17)
SMB_AM_WRITE_DAC        = (1<<18)
SMB_AM_WRITE_OWNER      = (1<<19)
SMB_AM_SYNC             = (1<<20)
SMB_AM_MAX_SEC          = (1<<24)
SMB_AM_MAX_ALLOWED      = (1<<25)
SMB_AM_GENERIC_ALL      = (1<<28)
SMB_AM_GENERIC_EXECUTE  = (1<<29)
SMB_AM_GENERIC_WRITE    = (1<<30)
SMB_AM_GENERIC_READ     = (1<<31)

SMB_AccessMask = {
    SMB_AM_NONE               :"NONE",
    SMB_AM_READ               :"READ",
    SMB_AM_WRITE              :"WRITE",
    SMB_AM_APPEND             :"APPEND",
    SMB_AM_READ_EA            :"READ_EA",
    SMB_AM_WRITE_EA           :"WRITE_EA",
    SMB_AM_EXECUTE            :"EXECUTE",
    SMB_AM_DELETE_CHILD       :"DELETE_CHILD",
    SMB_AM_READ_ATTR          :"READ_ATTR",
    SMB_AM_WRITE_ATTR         :"WRITE_ATTR",
    SMB_AM_DELETE             :"DELETE",
    SMB_AM_READ_CTRL          :"READ_CTRL",
    SMB_AM_WRITE_DAC          :"WRITE_DAC",
    SMB_AM_WRITE_OWNER        :"WRITE_OWNER",
    SMB_AM_SYNC               :"SYNC",
    SMB_AM_MAX_SEC            :"MAX_SEC",
    SMB_AM_MAX_ALLOWED        :"MAX_ALLOWED",
    SMB_AM_GENERIC_ALL        :"GENERIC_ALL",
    SMB_AM_GENERIC_EXECUTE    :"GENERIC_EXECUTE",
    SMB_AM_GENERIC_WRITE      :"GENERIC_WRITE",
    SMB_AM_GENERIC_READ       :"GENERIC_READ",
}

# Security Flags

SMB_SECFLAGS_CTX_TRACKING      = (1<<0)
SMB_SECFLAGS_EFFECTIVE_ONLY    = (1<<1)

SMB_SecurityFlags = {
    SMB_SECFLAGS_CTX_TRACKING   :"CTX_TRACKING",
    SMB_SECFLAGS_EFFECTIVE_ONLY :"EFFECTIVE_ONLY",
}



# Write Mode

SMB_WM_WRITETHROUGH        = 0x001
SMB_WM_RETURNREMAINING     = 0x002
SMB_WM_WRITERAW            = 0x004
SMB_WM_MSGSTART            = 0x008

SMB_WriteMode = {
    SMB_WM_WRITETHROUGH   :"WRITETHROUGH",
    SMB_WM_RETURNREMAINING:"RETURNREMAINING",
    SMB_WM_WRITERAW       :"WRITERAW",
    SMB_WM_MSGSTART       :"MSGSTART",
}

class SMBNullField(StrField):
    def __init__(self, name, default, fmt="H", remain=0, utf16=True):
        if utf16:
            UnicodeNullField.__init__(self, name, default, fmt, remain)
        else:
            StrNullField.__init__(self, name, default, fmt, remain)
    def addfield(self, pkt, s, val):
        if pkt.firstlayer().getlayer(SMB_Header).Flags2 & SMB_FLAGS2_UNICODE:
            return UnicodeNullField.addfield(self, pkt, s, val)
        else:
            return StrNullField.addfield(self, pkt, s, val)
    def getfield(self, pkt, s):
        smbhdr = pkt
        while not isinstance(smbhdr, SMB_Header) and smbhdr != None:
            smbhdr = smbhdr.underlayer

        if smbhdr and smbhdr.Flags2 & 0x8000:
            return UnicodeNullField.getfield(self, pkt, s)
        else:
            return StrNullField.getfield(self, pkt, s)

    def i2m(self, pkt, s):
        smbhdr = pkt
        while not isinstance(smbhdr, SMB_Header) and smbhdr != None:
            smbhdr = smbhdr.underlayer

        if smbhdr and smbhdr.Flags2 & 0x8000:
            return UnicodeNullField.i2m(self, pkt, s)
        else:
            return StrNullField.i2m(self, pkt, s)

    def i2repr(self, pkt, s):
        smbhdr = pkt
        while not isinstance(smbhdr, SMB_Header) and smbhdr != None:
            smbhdr = smbhdr.underlayer

        if smbhdr and smbhdr.Flags2 & 0x8000:
            return UnicodeNullField.i2repr(self, pkt, s)
        else:
            return StrNullField.i2repr(self, pkt, s)

    def size(self, pkt, s):
        smbhdr = pkt
        while not isinstance(smbhdr, SMB_Header) and smbhdr != None:
            smbhdr = smbhdr.underlayer

        if smbhdr and smbhdr.Flags2 & 0x8000:
            return UnicodeNullField.size(self, pkt, s)
        else:
            return StrNullField.size(self, pkt, s)






class UUIDField(StrFixedLenField):
    def __init__(self, name, default):
        StrFixedLenField.__init__(self, name, default, 16)
    def i2repr(self, pkt, v):
        return str(UUID(bytes_le=v))


class NBTSession(Packet):
    name="NBT Session Packet"
    fields_desc= [
        ByteEnumField("TYPE",0,
                      {0x00:"Session Message",
                       0x81:"Session Request",
                       0x82:"Positive Session Response",
                       0x83:"Negative Session Response",
                       0x84:"Retarget Session Response",
                       0x85:"Session Keepalive"}),
        BitField("RESERVED",0x00,7),
        BitField("LENGTH",0,17)
    ]

    def post_build(self, p, pay):
        self.LENGTH = len(pay)
        p = self.do_build()
        return p+pay

class NBTSession_Request(Packet):
    name="NBT Session Request"
    fields_desc= [
        StrNullField("CalledName","ALICE"),
        StrNullField("CallingName","BOB"),
    ]


class SMB_Header(Packet):
    name="SMB Header"
    fields_desc = [
        StrFixedLenField("Start",b'\xffSMB',4),
        XByteEnumField("Command",SMB_COM_NEGOTIATE,SMB_Commands),
        LEIntField("Status",0),
        #        XByteField("Flags",0x98),
        FlagsField("Flags", 0x98, 8, SMB_Header_Flags),
        #        XLEShortField("Flags2",SMB_FLAGS2_KNOWS_LONG_NAMES|SMB_FLAGS2_UNICODE),
        FlagsField("Flags2", SMB_FLAGS2_KNOWS_LONG_NAMES|
                   SMB_FLAGS2_UNICODE, -16, SMB_Header_Flags2),
        LEShortField("PIDHigh",0x0000),
        LELongField("Signature",0x0),
        LEShortField("Unused",0x0),
        LEShortField("TID",0xffff),
        LEShortField("PID",0),
        LEShortField("UID",0),
        LEShortField("MID",0),
    ]

class SMB_Parameters(Packet):
    name="SMB Parameters"
    fields_desc = [
        FieldLenField('Wordcount', None, fmt='B', length_of="Words"),
        StrLenField('Words', '', length_from = lambda pkt: pkt.Wordcount*2),
    ]

class SMB_Data(Packet):
    name="SMB Data"
    fields_desc = [
        FieldLenField(
            'ByteCount', None, fmt='<H', length_of="Bytes", adjust=lambda pkt,x:x+1),
        FixGapField("Padding", b'\x00'),
        StrLenField('Bytes', '', length_from = lambda pkt: pkt.ByteCount),
    ]

class SMB_Negociate_Protocol_Request_Tail(Packet):
    name="SMB Negociate Protocol Request Tail"
    fields_desc=[
        ByteField("BufferFormat",0x02),
        StrNullField("BufferData","NT LM 0.12"),
    ]


class SMB_Negociate_Protocol_Request_Counts(Packet):
    name = "SMB Negociate_Protocol_Request_Counts"
    fields_desc = [
        ByteField("WordCount",0),
        #        LEShortField("ByteCount",12),
        FieldLenField("ByteCount", 12, fmt='<H', length_of="Requests"),
        PacketListField(
            "Requests", None, SMB_Negociate_Protocol_Request_Tail, length_from=lambda x:x.ByteCount)
    ]


# page 60
# we support nt lm 0.12
# therefore we only need the response on 60/61
# ByteCount is actually the sum of len(ServerGUID) and len(SecurityBlob)
# but it is not required atm, and scapy does not support combined fieldlens
class SMB_Negociate_Protocol_Response(Packet):
    name="SMB Negociate Response"
    smb_cmd = SMB_COM_NEGOTIATE #0x72
    fields_desc = [
        ByteField("WordCount",17),
        LEShortField("DialectIndex",0),
        XByteField("SecurityMode",3),
        LEShortField("MaxMPXCount",1),
        LEShortField("MaxVCs",1),
        LEIntField("MaxBufferS",4096),
        LEIntField("MaxRawBuffer",65536),
        LEIntField("SessionKey",0),
        FlagsField(
            "Capabilities", 0x8000e3fd, -32, SMB_Negotiate_Capabilities),
        NTTimeField("SystemTime",datetime.datetime.now()),
        ShortField("SystemTimeZone",0xc4ff),
        ByteField("KeyLength", 0),
        #LEShortField("ByteCount", 16),
        MultiFieldLenField("ByteCount", None, fmt='<H', length_of=(
            "EncryptionKey","OemDomainName","ServerName", "ServerGUID", "SecurityBlob")),
        # without CAP_EXTENDED_SECURITY
        ConditionalField(StrLenField("EncryptionKey", b'',length_from=lambda x: 0),
                         lambda x: not x.Capabilities & CAP_EXTENDED_SECURITY),
        ConditionalField(UnicodeNullField(
            "OemDomainName", "WORKGROUP"), lambda x: not x.Capabilities & CAP_EXTENDED_SECURITY),
        # In [MS-SMB].pdf page 49,
        # "ServerName" field needed for case without CAP_EXTENDED_SECURITY
        ConditionalField(UnicodeNullField(
            "ServerName", "HOMEUSER-3AF6FE"), lambda x: not x.Capabilities & CAP_EXTENDED_SECURITY),
        # with CAP_EXTENDED_SECURITY
        ConditionalField(StrLenField("ServerGUID", b'\x0B\xFF\x65\x38\x54\x7E\x6C\x42\xA4\x3E\x12\xD2\x11\x97\x16\x44',
                                     length_from=lambda x: 16), lambda x: x.Capabilities & CAP_EXTENDED_SECURITY),
        ConditionalField(StrLenField("SecurityBlob", b'', length_from=lambda x: 0),
                         lambda x: x.Capabilities & CAP_EXTENDED_SECURITY),
    ]

class SMB_Sessionsetup_ESEC_AndX_Request(Packet):
    name="SMB Sessionsetup ESEC AndX Request"
    fields_desc = [
        ByteField("WordCount",12),
        ByteEnumField("AndXCommand",0xff,SMB_Commands),
        ByteField("AndXReserved",0),
        LEShortField("AndXOffset",96),
        LEShortField("MaxBufferSize",2920),
        LEShortField("MaxMPXCount",50),
        LEShortField("VCNumber",0),
        LEIntField("SessionKey",0),
        FieldLenField(
            "SecurityBlobLength", None, fmt='<H', length_of="SecurityBlob"),
        LEIntField("Reserved",0),
        #        XLEIntField("Capabilities",0x05),
        FlagsField("Capabilities", 0x8000e3fd, -32, SMB_Negotiate_Capabilities),
        LEShortField("ByteCount",35),
        StrLenField(
            "SecurityBlob", "Pass", length_from=lambda x:x.SecurityBlobLength),
        ConditionalField(StrLenField("Padding", "\x00", length_from=lambda x:(
            x.SecurityBlobLength+1)%2), lambda x:x.underlayer.Flags2 & SMB_FLAGS2_UNICODE),
        #        StrFixedLenField("Padding", "\x00", length_from=lambda x:(x.SecurityBlobLength+1)%2),
        SMBNullField(
            "NativeOS","Windows", utf16=lambda x:x.underlayer.Flags2 & SMB_FLAGS2_UNICODE),
        SMBNullField("NativeLanManager","Windows",
                     utf16=lambda x:x.underlayer.Flags2 & SMB_FLAGS2_UNICODE),
        #        UnicodeNullField("PrimaryDomain","WORKGROUP"),
        StrFixedLenField(
            "Extrabytes", b'', length_from=lambda x:x.lengthfrom_Extrabytes())
    ]
    def lengthfrom_Extrabytes(self):
        x = self.ByteCount
        x -= len(self.SecurityBlob)
        if hasattr(self,'Padding') and self.Padding != None:
            x -= len(self.Padding)
        x -= len(self.NativeOS)
        x -= len(self.NativeLanManager)
        return x


class SMB_Sessionsetup_ESEC_AndX_Response(Packet):
    name="SMB Sessionsetup ESEC AndX Response"
    smb_cmd = SMB_COM_SESSION_SETUP_ANDX # 0x73
    fields_desc = [
        ByteField("WordCount",4),
        ByteEnumField("AndXCommand",0xff,SMB_Commands),
        ByteField("AndXReserved",0),
        LEShortField("AndXOffset",0),
        XLEShortField("Action",1),
        FieldLenField(
            "SecurityBlobLength", None, fmt='<H', length_of="SecurityBlob"),
        MultiFieldLenField("ByteCount", None, fmt='<H', length_of=(
            "Padding","NativeOS", "NativeLanManager", "PrimaryDomain","SecurityBlob")),
        StrLenField(
            "SecurityBlob", "", length_from=lambda x:x.SecurityBlobLength),
        ConditionalField(StrFixedLenField("Padding", "\x00", length_from=lambda x:(
            len(x.SecurityBlob)+1)%2), lambda x:x.underlayer.Flags2 & SMB_FLAGS2_UNICODE),
        SMBNullField("NativeOS","Windows 5.1",
                     utf16=lambda x:x.underlayer.Flags2 & SMB_FLAGS2_UNICODE),
        SMBNullField("NativeLanManager","Windows 2000 LAN Manager",
                     utf16=lambda x:x.underlayer.Flags2 & SMB_FLAGS2_UNICODE),
        SMBNullField("PrimaryDomain","WORKGROUP",
                     utf16=lambda x:x.underlayer.Flags2 & SMB_FLAGS2_UNICODE),
    ]
#    def post_build(self, p, pay):
#        p.

# pre nt lm 0.12
# not supported
#class SMB_Sessionsetup_AndX_Request(Packet):
#    name="SMB Sessionsetup AndX Request"
#    fields_desc = [
#        ByteField("WordCount",10),
#        ByteEnumField("AndXCommand",0xff,SMB_Commands),
#        ByteField("Reserved1",0),
#        LEShortField("AndXOffset",0),
#        LEShortField("MaxBufferS",2920),
#        LEShortField("MaxMPXCount",50),
#        LEShortField("VCNumber",0),
#        LEIntField("SessionKey",0),
#        FieldLenField("PasswordLength", None, fmt='<H', length_of="Password"),
#        LEIntField("Reserved2",0),
#        LEShortField("ByteCount",35),
#        StrLenField("Password", "Pass", length_from=lambda x:x.PasswordLength),
#        SMBNullField("Account", "", utf16=lambda x:x.underlayer.Flags2 & SMB_FLAGS2_UNICODE),
#        SMBNullField("PrimaryDomain","WORKGROUP", utf16=lambda x:x.underlayer.Flags2 & SMB_FLAGS2_UNICODE),
#        SMBNullField("NativeOS","Windows", utf16=lambda x:x.underlayer.Flags2 & SMB_FLAGS2_UNICODE),
#        SMBNullField("NativeLanManager","Windows", utf16=lambda x:x.underlayer.Flags2 & SMB_FLAGS2_UNICODE),
#    ]
#
#class SMB_Sessionsetup_AndX_Response(Packet):
#    name="SMB Sessionsetup AndX Response"
#    smb_cmd = 0x73
#    fields_desc = [
#        ByteField("WordCount",4),
#        ByteEnumField("AndXCommand",0xff,SMB_Commands),
#        ByteField("Reserved1",0),
#        LEShortField("AndXOffset",0),
#        XLEShortField("Action",1),
#        FieldLenField("BlobLength", None, fmt='<H', length_of="Blob"),
#        LEShortField("ByteCount",55),
#        StrLenField("Blob", b"\xa1\x07\x30\x05\xa0\x03\x0a\x01", length_from=lambda x:x.BlobLength),
#        StrNullField("NativeOS","Windows 5.1"),
#        StrNullField("NativeLanManager","Windows 2000 LAN Manager"),
#        StrNullField("PrimaryDomain","WORKGROUP"),
#    ]


# CIFS-TR-1p00_FINAL.pdf 665616b44740177c86051c961fdf6768
# page 65
# WordCount 13 is used to negotiate "NT LM 0.12" if the server does not support
# Extended Security
class SMB_Sessionsetup_AndX_Request2(Packet):
    name="SMB Sessionsetup AndX Request2"
    fields_desc = [
        ByteField("WordCount",13),
        ByteEnumField("AndXCommand",0xff,SMB_Commands),
        ByteField("AndXReserved",0),
        LEShortField("AndXOffset",0),
        LEShortField("MaxBufferSize",2920),
        LEShortField("MaxMPXCount",50),
        LEShortField("VCNumber",0),
        LEIntField("SessionKey",0),
        FieldLenField("PasswordLength", None, fmt='<H', length_of="Password"),
        FieldLenField(
            "UnicodePasswordLength", None, fmt='<H', length_of="UnicodePassword"),
        LEIntField("Reserved2",0),
        #        XLEIntField("Capabilities",0),
        FlagsField("Capabilties", 0x8000e3fd, -32, SMB_Negotiate_Capabilities),
        LEShortField("ByteCount",35),
        StrLenField("Password", "Pass", length_from=lambda x:x.PasswordLength),
        StrLenField(
            "UnicodePassword", "UniPass", length_from=lambda x:x.UnicodePasswordLength),
        ConditionalField(StrLenField("Padding", "\x00", length_from=lambda x:(
            x.PasswordLength+1)%2), lambda x:x.underlayer.Flags2 & SMB_FLAGS2_UNICODE),
        SMBNullField(
            "Account", "", utf16=lambda x:x.underlayer.Flags2 & SMB_FLAGS2_UNICODE),
        SMBNullField("PrimaryDomain","WORKGROUP",
                     utf16=lambda x:x.underlayer.Flags2 & SMB_FLAGS2_UNICODE),
        SMBNullField(
            "NativeOS","Windows", utf16=lambda x:x.underlayer.Flags2 & SMB_FLAGS2_UNICODE),
        SMBNullField("NativeLanManager","Windows",
                     utf16=lambda x:x.underlayer.Flags2 & SMB_FLAGS2_UNICODE),
        StrFixedLenField(
            "Extrabytes", b"\x00", length_from=lambda x: x.lengthof_Extrabytes()),
    ]
    def lengthof_Extrabytes(self):
        bc = self.ByteCount
        bc = bc - len(self.Account) - len(self.PrimaryDomain) - \
            len(self.NativeOS) - len(self.NativeLanManager)
        if hasattr(self,'Padding') and self.Padding is not None:
            bc = bc - len(self.Padding)
        return bc

class SMB_Sessionsetup_AndX_Response2(Packet):
    name="SMB Sessionsetup AndX Response2"
    smb_cmd = SMB_COM_SESSION_SETUP_ANDX #0x73
    fields_desc = [
        ByteField("WordCount",3),
        ByteEnumField("AndXCommand",0xff,SMB_Commands),
        ByteField("Reserved1",0),
        LEShortField("AndXOffset",0),
        XLEShortField("Action",1),
        MultiFieldLenField("ByteCount", None, fmt='<H', length_of=(
            "Padding","NativeOS", "NativeLanManager", "PrimaryDomain")),
        ConditionalField(StrFixedLenField(
            "Padding", b'\0', 1), lambda x:x.underlayer.Flags2 & SMB_FLAGS2_UNICODE),
        SMBNullField("NativeOS","Windows 5.1",
                     utf16=lambda x:x.underlayer.Flags2 & SMB_FLAGS2_UNICODE),
        SMBNullField("NativeLanManager","Windows 2000 LAN Manager",
                     utf16=lambda x:x.underlayer.Flags2 & SMB_FLAGS2_UNICODE),
        SMBNullField("PrimaryDomain","WORKGROUP",
                     utf16=lambda x:x.underlayer.Flags2 & SMB_FLAGS2_UNICODE),
    ]

# CIFS-TR-1p00_FINAL.pdf 665616b44740177c86051c961fdf6768
# page 35
# Strings that are never passed in Unicode are:
# * The service name string in the Tree_Connect_AndX SMB.
class SMB_Treeconnect_AndX_Request(Packet):
    name = "SMB Treeconnect AndX Request"
    fields_desc = [
        ByteField("WordCount",4),
        ByteEnumField("AndXCommand",0xff,SMB_Commands),
        ByteField("Reserved1",0),
        LEShortField("AndXOffset",0),
        XLEShortField("Flags",0x2),
        FieldLenField("PasswordLength", None, fmt='<H', length_of="Password"),
        LEShortField("ByteCount",18),
        StrLenField("Password", "Pass", length_from=lambda x:x.PasswordLength),
        ConditionalField(StrFixedLenField("Padding", b'\0', 1), lambda x:
                         x.underlayer.Flags2 & SMB_FLAGS2_UNICODE and len(x.Password)%2 == 0),
        SMBNullField("Path","\\\\WIN2K\\IPC$",
                     utf16=lambda x:x.underlayer.Flags2 & SMB_FLAGS2_UNICODE),
        StrNullField("Service","IPC"),
        # StrFixedLenField("Extrabytes", b"\x00", length_from=lambda x:
        # x.ByteCount - len(x.Password) - ( hasattr(x, 'Padding') ?
        # len(x.Padding) : 0 ) - len(x.Path) - len(x.Service)),
        StrFixedLenField(
            "Extrabytes", b"\x00", length_from=lambda x: x.lengthof_Extrabytes()),
    ]
    def lengthof_Extrabytes(self):
        x = self.ByteCount
        x -= len(self.Password)
        if hasattr(self,'Padding') and self.Padding != None:
            x -= len(self.Padding)
        x -= len(self.Path)
        x -= len(self.Service)
        return x




class SMB_Treedisconnect(Packet):
    name = "SMB Tree Disconnect"
    smb_cmd = SMB_COM_TREE_DISCONNECT # 0x71
    fields_desc = [
        ByteField("WordCount",0),
        LEShortField("ByteCount",0),
    ]

class SMB_Treeconnect_AndX_Response(Packet):
    name="SMB Treeconnect AndX Response"
    smb_cmd = SMB_COM_TREE_CONNECT_ANDX #0x75
    fields_desc = [
        ByteField("WordCount",3),
        ByteEnumField("AndXCommand",0xff,SMB_Commands),
        ByteField("Reserved1",0),
        LEShortField("AndXOffset",46), #windows xp gives senseless 46
        XLEShortField("OptSupport",1),
        #        LEShortField("ByteCount",5),
        MultiFieldLenField(
            "ByteCount", None, fmt='<H', length_of=("Service","NativeFileSystem")),
        StrNullField("Service","IPC"),
        StrNullField("NativeFileSystem",""),
    ]

#[MS-SMB].pdf
#Page 62
class SMB_Treeconnect_AndX_Response_Extended(Packet):
    name="SMB Treeconnect AndX Response Extended"
    smb_cmd = SMB_COM_TREE_CONNECT_ANDX #0x75
    fields_desc = [
        ByteField("WordCount",7),
        ByteEnumField("AndXCommand",0xff,SMB_Commands),
        ByteField("Reserved1",0),
        LEShortField("AndXOffset",56), #windows xp gives senseless 56
        XLEShortField("OptSupport",0x0001),
        FlagsField("MaximalShareAccessRights", 0x01ff, -32, SMB_AccessMask),
        FlagsField(
            "GuestMaximalShareAccessRights", 0x01ff, -32, SMB_AccessMask),
        #        LEShortField("ByteCount",7),
        MultiFieldLenField("ByteCount", None, fmt='<H', length_of=(
            "Service","Padding","NativeFileSystem")),
        StrNullField("Service","IPC"),
        ConditionalField(StrFixedLenField(
            "Padding", b'\0', 2), lambda x:x.underlayer.Flags2 & SMB_FLAGS2_UNICODE),
        StrNullField("NativeFileSystem",""),
    ]

# Used when the error's return is needed
class SMB_Treeconnect_AndX_Response2(Packet):
    name="SMB Treeconnect AndX Response2"
    smb_cmd = SMB_COM_TREE_CONNECT_ANDX #0x75
    fields_desc = [
        ByteField("WordCount",0),
        LEShortField("ByteCount",0),
    ]

class SMB_Error_Response(Packet):
    name="SMB Error Response"
    fields_desc = [
        ByteField("WordCount",0),
        LEShortField("ByteCount",0),
    ]


# page 76
class SMB_NTcreate_AndX_Request(Packet):
    name = "SMB NTcreate AndX Request"
    fields_desc = [
        ByteField("WordCount",24),
        ByteEnumField("AndXCommand",0xff,SMB_Commands),
        ByteField("Reserved1",0),
        LEShortField("AndXOffset",0),
        ByteField("Reserved2",0),
        LEShortField("FileNameLen",0x2),
        FlagsField("CreateFlags", 0, -32, SMB_CreateFlags),
        #        XLEIntField("CreateFlags",0),
        XLEIntField("RootFID",0),
        FlagsField("AccessMask", 0, -32, SMB_AccessMask),
        #        XLEIntField("AccessMask",0),
        LELongField("AllocationSize",0),
        FlagsField("FileAttributes", 0, -32, SMB_FileAttributes),
        FlagsField("ShareAccess", 3, -32, SMB_ShareAccess),
        LEIntField("Disposition",1),
        FlagsField("CreateOptions", 0, -32, SMB_CreateOptions),
        #        XLEIntField("CreateOptions",0),
        LEIntField("Impersonation",1),
        FlagsField("SecurityFlags", 0, -8, SMB_SecurityFlags),
        #        XByteField("SecurityFlags",0),
        LEShortField("ByteCount",0),
        #        FixGapField("FixGap", b'\0'),
        ConditionalField(StrFixedLenField(
            "Padding", b'\0', 1), lambda x:x.underlayer.Flags2 & SMB_FLAGS2_UNICODE),
        SMBNullField("FileName","\\lsarpc", utf16=lambda x:x.underlayer.Flags2 & SMB_FLAGS2_UNICODE),
        #StrLenField("FileName", None, length_from=lambda pkt:pkt.FileNameLen),
        StrFixedLenField(
            "Extrabytes", b'', length_from=lambda x:x.lengthfrom_Extrabytes())
    ]
    def lengthfrom_Extrabytes(self):
        x = self.ByteCount
        if hasattr(self,'Padding') and self.Padding != None:
            x -= len(self.Padding)
        x -= len(self.FileName)
        return x

# page 77

class SMB_NTcreate_AndX_Response(Packet):
    name="SMB NTcreate AndX Response"
    smb_cmd = SMB_COM_NT_CREATE_ANDX #0xa2
    #strange_packet_tail = bytes.fromhex(
    #    '000000000000000000000000000000000000000000009b0112009b0112000000')
    fields_desc = [
        ByteField("WordCount",34),
        ByteEnumField("AndXCommand",0xff,SMB_Commands),
        ByteField("Reserved1",0),
        LEShortField("AndXOffset",0),
        XByteField("OpLockLevel",0),
        XLEShortField("FID",0x4000),
        XLEIntField("CreateAction",1),
        NTTimeField("Created",0),
        NTTimeField("LastAccess",0),
        NTTimeField("LastModified",0),
        NTTimeField("Change",0),
        FlagsField("FileAttributes", 0x80, -32, SMB_FileAttributes),
        LELongField("AllocationSize",0),
        LELongField("EndOfFile",0),
        #LEShortField("FileType",2),
        LEShortEnumField("FileType", 0, SMB_ResourceTypes),
        XLEShortField("IPCstate",0x0007),
        ByteField("IsDirectory",0),
        LEShortField("ByteCount",0),
    #    StrLenField("FixStrangeness", strange_packet_tail,
    #                length_from=lambda x:len(x.strange_packet_tail)),
    ]

class SMB_NTcreate_AndX_Response_Extended(Packet):
    name = "SMB NTcreate AndX Response Extended"
    smb_cmd = SMB_COM_NT_CREATE_ANDX
    fields_desc = [
        ByteField("WordCount", 0x2a),
        ByteEnumField("AndXCommand",0xff,SMB_Commands),
        ByteField("Reserved1",0),
        LEShortField("AndXOffset",0),
        XByteField("OpLockLevel",0),
        XLEShortField("FID",0x4000),
        XLEIntField("CreateAction",1),
        NTTimeField("Created",0),
        NTTimeField("LastAccess",0),
        NTTimeField("LastModified",0),
        NTTimeField("Change",0),
        FlagsField("FileAttributes", 0x80, -32, SMB_FileAttributes),
        LELongField("AllocationSize",0),
        LELongField("EndOfFile",0),
        #LEShortField("FileType",2),
        LEShortEnumField("FileType", 0, SMB_ResourceTypes),
        XLEShortField("IPCstate",0x0007),
        ByteField("IsDirectory",0),
        StrFixedLenField("VolumeGUID", b"\0", length=16),
        LELongField("FileId", 0),
        LEIntField("MaximalAccessRights", 0x001f01ff),
        LEIntField("MaximalAccessRights", 0x001f01ff),
        LEShortField("ByteCount",0),
    #    StrLenField("FixStrangeness", strange_packet_tail,
    #                length_from=lambda x:len(x.strange_packet_tail)),
    ]



class SMB_NTcreate_AndX_Response_ERROR(Packet):
    name="SMB NTcreate AndX Response"
    smb_cmd = SMB_COM_NT_CREATE_ANDX #0xa2
    fields_desc = [
        ByteField("WordCount",0),
        LEShortField("ByteCount",0),
    ]


# page 83
# the manual says there is a Padding Byte right after the bytecount
# the padding length is the difference of ByteCount and Remaining

class SMB_Write_AndX_Request(Packet):
    name = "SMB Write AndX Request"
    fields_desc = [
        ByteField("WordCount",14),
        ByteEnumField("AndXCommand",0xff,SMB_Commands),
        ByteField("AndXReserved",0),
        LEShortField("AndXOffset",0),
        XLEShortField("FID",0),
        LEIntField("Offset",0),
        XIntField("Reserved2",0xffffffff),
        FlagsField("WriteMode", 0, -16, SMB_WriteMode),
        FieldLenField("Remaining", None, fmt='<H', length_of="Data"),
        LEShortField("DataLenHigh",0), #multiply with 64k
        LEShortField("DataLenLow",0),
        LEShortField("DataOffset",0),
        ConditionalField(LEIntField("HighOffset",0), lambda x:x.WordCount==14),
        LEShortField("ByteCount",  0),
        ConditionalField(LEShortField("PipeWriteLen", 0), lambda x:
                         x.WriteMode & SMB_WM_MSGSTART and x.WriteMode & SMB_WM_WRITERAW),
        #StrLenField("Padding", None, length_from=lambda x: x.ByteCount-((x.DataLenHigh<<16)|x.DataLenLow)),
        ByteField("Pad", 0),
        StrLenField("Data", b"", length_from=lambda x:(
            (x.DataLenHigh<<16)|x.DataLenLow)),
    ]

    def lengthfrom_Pad(self):
        x = 3 * 1
        x += 8 * 2
        x += 2 * 4
        if hasattr(self,'HighOffset'):
            x += 4
        if hasattr(self,'PipeWriteLen'):
            x += 2
        return self.ByteCount - x

class SMB_Write_AndX_Response(Packet):
    name = "SMB Write AndX Response"
    smb_cmd = SMB_COM_WRITE_ANDX #0x2f
    fields_desc = [
        ByteField("WordCount",6),
        ByteEnumField("AndXCommand",0xff,SMB_Commands),
        ByteField("AndXReserved",0),
        LEShortField("AndXOffset",47),
        LEShortField("CountLow",0),
        LEShortField("Remaining",0xffff),
        LEShortField("CountHigh",0), #multiply with 64k
        LEShortField("Reserved",0),
        LEShortField("ByteCount",0),
    ]


class SMB_Write_Request(Packet):
    # http://msdn.microsoft.com/en-us/library/ee441864%28v=PROT.13%29.aspx
    name = "SMB Write Request"
    smb_cmd = SMB_COM_WRITE
    fields_desc = [
        ByteField("WordCount",6),
        XLEShortField("FID",0),
        XLEShortField("CountOfBytesToWrite",0),
        XIntField("WriteOffsetInBytes",0),
        XLEShortField("EstimateOfRemainingBytesToBeWritten",0),
        LEShortField("ByteCount",0),
        ByteField("BufferFormat",0x01),
        FieldLenField("DataLength",None, fmt='<H', length_of="Data"),
        StrLenField("Data",b"",length_from=lambda x:x.DataLength)
    ]

class SMB_Write_Response(Packet):
    name = "SMB Write Response"
    smb_cmd = SMB_COM_WRITE
    fields_desc = [
        ByteField("WordCount",1),
        LEShortField("CountOfBytesWritten",0),
        LEShortField("ByteCount",0),
    ]


class SMB_Rename_Request(Packet):
    name = "SMB Rename Request"
    smb_cmd = SMB_COM_RENAME
    fields_desc = [
        ByteField("WordCount", 1),
        FlagsField("SearchAttributes", 0, -16, SMB_FileAttributes),
        LEShortField("ByteCount", 0),
        ByteField("BufferFormat", 4),
        SMBNullField("OldFileName", b"\x00", utf16=lambda x:x.underlayer.Flags2 & SMB_FLAGS2_UNICODE),
        ByteField("BufferFormat2", 4),
        ByteField("Reserved", 0),
        SMBNullField("NewFileName", b"\x00", utf16=lambda x:x.underlayer.Flags2 & SMB_FLAGS2_UNICODE),
    ]





# page 82
# I have no idea why we need the FixGap's
class SMB_Read_AndX_Request(Packet):
    name = "SMB Read AndX Request"
    fields_desc = [
        ByteField("WordCount",10),
        ByteEnumField("AndXCommand",0xff,SMB_Commands),
        ByteField("AndXReserved",0),
        LEShortField("AndXOffset",0),
        XLEShortField("FID",0),
        LEIntField("Offset",0),
        LEShortField("MaxCountLow",0),
        LEShortField("MinCount",0),
        IntField("Timeout", 0xffffffff),
        LEShortField("Remaining",0),
        ConditionalField(
            LEIntField("HighOffset", 0), lambda x:x.WordCount==12),
        LEShortField("ByteCount",0),
        IntField("FixGap2", 0),
    ]

class SMB_Read_AndX_Response(Packet):
    name = "SMB Read AndX Response"
    smb_cmd = SMB_COM_READ_ANDX #0x2e
    fields_desc = [
        ByteField("WordCount",12),
        ByteEnumField("AndXCommand",0xff,SMB_Commands),
        ByteField("Reserved1",0),
        LEShortField("AndXOffset",0),
        LEShortField("Remaining",0),
        LEShortField("DataCompactMode",0),
        LEShortField("Reserved2",0),
        LEShortField("DataLenLow",0),
        LEShortField("DataOffset",60),
        LEIntField("DataLenHigh",0), #multiply with 64k
        StrLenField("Reserved3", b"\0"*6, length_from=lambda x:6),
    ]

# page 44
# padding is negotiable

class SMB_Trans_Request(Packet):
    name = "SMB Trans Request"
    fields_desc = [
        ByteField("WordCount",16),
        LEShortField("TotalParamCount",0),
        LEShortField("TotalDataCount",0),
        LEShortField("MaxParamCount",0),
        LEShortField("MaxDataCount",0),
        ByteField("MaxSetupCount",0),
        ByteField("Reserved1",0),
        XLEShortField("Flags",0),
        LEIntField("Timeout",0),
        ShortField("Reserved2",0),
        FieldLenField("ParamCount", 0, fmt='<H', count_of="Param"),
        LEShortField("ParamOffset",0),
        LEShortField("DataCount",0),
        LEShortField("DataOffset",0),
        FieldLenField("SetupCount", 0, fmt='B', count_of="Setup"),
        ByteField("Reserved3",0),
        FieldListField(
            "Setup", 0, ShortField("", 0), count_from = lambda pkt: pkt.SetupCount),
        LEShortField("ByteCount",0),
        ConditionalField(StrFixedLenField(
            "Padding", b'\0', 1), lambda x:x.underlayer.Flags2 & SMB_FLAGS2_UNICODE),
        SMBNullField("TransactionName",b"\\PIPE\\",
                     utf16=lambda x:x.underlayer.Flags2 & SMB_FLAGS2_UNICODE),
        StrFixedLenField("Pad", b"", length_from=lambda x:x.lengthfrom_Pad()),
        FieldListField(
            "Param", 0, XByteField("", 0), count_from = lambda pkt: pkt.ParamCount),
        StrFixedLenField(
            "Pad1", b"", length_from=lambda x:x.lengthfrom_Pad1()),
        #        StrFixedLenField("Pad1", b"", length_from=lambda x:x.lengthfrom_Pad1() ),
    ]
    def lengthfrom_Pad(self):
        if self.ParamOffset == 0:
            return 0
        r = self.underlayer.size()    # underlayer size removed
        r += 5                        # 5 byte vars
        r += 11*2                    # 11 words
        r += 4                        # 1 int
        r += self.SetupCount*2            # SetupCount words
        if hasattr(self, 'Padding') and self.Padding != None:
            r += len(self.Padding)        # optional Padding
        r += len(self.TransactionName)    # TransactionName
#        print("r %i usize %i txn %i" % ( r, self.underlayer.size(), len(self.TransactionName)))
        r = self.ParamOffset - r
        return r

    def lengthfrom_Pad1(self):
        if self.DataOffset == 0:
            return 0
        r = self.underlayer.size()    # underlayer size removed
        r += 5                        # 5 byte vars
        r += 11*2                    # 11 words
        r += 4                        # 1 int
        r += self.SetupCount*2            # SetupCount words
        if hasattr(self, 'Padding') and self.Padding != None:
            r += len(self.Padding)        # optional Padding
        r += len(self.TransactionName)    # TransactionName
        r += len(self.Pad)                # Param Padding
        r += self.ParamCount            # Param
        r = self.DataOffset - r
        return r


class SMB_Trans_Response(Packet):
    name = "SMB Trans Response"
    smb_cmd = SMB_COM_TRANSACTION #0x25
    fields_desc = [
        ByteField("WordCount",10),
        LEShortField("TotalParamCount",0),
        LEShortField("TotalDataCount",0),
        LEShortField("Reserved1",0),
        LEShortField("ParamCount",0),
        LEShortField("ParamOffset",56),
        LEShortField("ParamDisplacement",0),
        LEShortField("DataCount",0),
        LEShortField("DataOffset",56),
        LEShortField("DataDisplacement",0),
        ByteField("SetupCount",0),
        ByteField("Reserved2",0),
    ]

class SMB_Trans_Response_Simple(Packet):
    name = "SMB Trans Response Simple"
    smb_cmd = SMB_COM_TRANSACTION #0x25
    fields_desc = [
        ByteField("WordCount",0),
        LEShortField("ByteCount",0),
    ]

class SMB_STRUCT_QUERY_FULL_FS_SIZE_INFO(Packet):
    name = "SMB Query Full FS Size Info"
    fields_desc = [
        LELongField("TotalAllocationUnits", 0),
        LELongField("CallerFreeAllocationUnits", 0),
        LELongField("ActualFreeAllocationUnits", 0),
        LEIntField("SectorsPerAllocationUnit", 0),
        LEIntField("BytesPerSector", 0),
        ]

class SMB_STRUCT_QUERY_FS_VOLUME_INFO(Packet):
    name = "SMB Query FS Volume Info"
    fields_desc = [
        LELongField("VolumeCreationTime", 0),
        LEIntField("SerialNumber", 132),
        FieldLenField("VolumeLabelSize", None, fmt="<I", length_of="VolumeLabel"),
        LEShortField("Reserved", 0),
        StrField("VolumeLabel", ""),
    ]


class SMB_STRUCT_QUERY_FS_SIZE_INFO(Packet):
    name = "SMB Query FS Size Info"
    fields_desc = [
        LELongField("TotalAllocationUnits", 0),
        LELongField("TotalFreeAllocationUnits", 0),
        LEIntField("SectorsPerAllocationUnit", 0),
        LEIntField("BytesPerSector", 0),
    ]
        

class SMB_STRUCT_QUERY_FS_DEVICE_INFO(Packet):
    name = "SMB Query FS Device Info"
    fields_desc =  [
        LEIntField("DeviceType", 0),
        LEIntField("DeviceCharacteristics", 0),
    ]

# FileSystemAttributes
FILE_CASE_SENSITIVE_SEARCH  = 0x00000001
FILE_CASE_PRESERVED_NAMES   = 0x00000002
FILE_UNICODE_ON_DISK        = 0x00000004
FILE_PERSISTENT_ACLS        = 0x00000008
FILE_FILE_COMPRESSION       = 0x00000010
FILE_VOLUME_IS_COMPRESSED   = 0x00008000

class SMB_STRUCT_QUERY_FS_ATTRIBUTE_INFO(Packet):
    name = "SMB Query FS Attribute Info"
    fields_desc = [
        LEIntField("FileSystemAttributes", 0), 
        LEIntField("MaxFileNameLengthInBytes", 255), 
        FieldLenField("LengthOfFileSystemName", None, fmt="<I", length_of="FileSystemName"), 
        StrLenField("FileSystemName", None),
    ]

#class SMB_STRUCT_INFO_ALLOCATION(Packet):
#class SMB_STRUCT_INFO_VOLUME(Packet):
# MS-CIFS p.454
class SMB_STRUCT_FIND_FILE_BOTH_DIRECTORY_INFO(Packet):
    name = "SMB Find File Both Directory Info"
    fields_desc = [
        #FieldLenField("NextEntryOffset", None, fmt="<I", length_of="FileName", adjust = lambda pkt,x:x+94 if pkt.hasNext else 0),
        LEIntField("NextEntryOffset", 0),
        LEIntField("FileIndex", 0),
        LELongField("CreationTime", 0),
        LELongField("LastAccessTime", 0),
        LELongField("LastWriteTime", 0),
        LELongField("LastChangeTime", 0),
        LELongField("EndOfFile", 0),
        LELongField("AllocationSize", 0),
        FlagsField("ExtFileAttributes", SMB_EXT_ATTR_NORMAL, -32, SMB_ExtFileAttributes),
        FieldLenField("FileNameLength", None, fmt="<I", length_of="FileName"),
        LEIntField("EaSize", 0),
        ByteField("ShortNameLength", 0),
        ByteField("Reserved", 0),
        StrFixedLenField("ShortName", 0, length=24),
        #SMBNullField("ShortName", None, utf16=lambda x:x.getlayer(SMB_Header).Flags2 & SMB_FLAGS2_UNICODE),
        StrField("FileName", None),# length_from=lambda x:x.FileNameLength),# utf16=lambda x:x.getlayer(SMB_Header).Flags2 & SMB_FLAGS2_UNICODE),
    ]

##
##   Trans2 SET FILE/PATH Information Level Codes and data structures
##  
##      MS-CIFS p.66
##      MS-CIFS p
##

#SMB_INFO_STANDARD               = 0x0001
SMB_INFO_SET_EAS                = 0x0002
SMB_SET_FILE_BASIC_INFO         = 0x0101
SMB_SET_FILE_DISPOSITION_INFO   = 0x0102
SMB_SET_FILE_ALLOCATION_INFO    = 0x0103
SMB_SET_FILE_END_OF_FILE_INFO   = 0x0104

class SMB_Trans2_SET_FILE_INFO_Request(Packet):
    name = "SMB Trans2 SET FILE INFO Request"
    fields_desc = [
        #MultiFieldLenField("ByteCount", None, fmt='<H', length_of=("Name","Pad", "FID",  "InformationLevel", "Reserved", "Pad1", "Data")),
        LEShortField("ByteCount", 0),
        ByteField("Name", 0),
        StrFixedLenField("Pad", b"", length_from=lambda x:x.lengthfrom_Pad()),
        XLEShortField("FID", 0x4000),
        XLEShortField("InformationLevel", 0),
        LEShortField("Reserved", 0),
        StrFixedLenField("Pad1", b"", length_from=lambda x:x.lengthfrom_Pad1()),
        #PacketListField("Data", None, Packet),
    ]
    def lengthfrom_Pad(self):
        if self.underlayer.ParamOffset == 0:
            return 0
        pad = self.underlayer.ParamOffset - self.underlayer.size() 
        pad -= 32 # SMB header
        pad -= 2 # ByteCount in SMB Data
        pad -= 1 # Name in SMB Data
        return pad

    def lengthfrom_Pad1(self):
       if self.underlayer.DataOffset == 0:
           return 0
       pad = self.underlayer.DataOffset
       pad -= self.underlayer.ParamOffset
       pad -= self.underlayer.ParamCount
       return pad

# only supports the data structs from LANMAN2.0
class SMB_Trans2_SET_PATH_INFO_Request(Packet):
    name = "SMB Trans2 SET PATH INFO Request"
    fields_desc = [
        MultiFieldLenField("ByteCount", None, fmt='<H', length_of=("Name","Pad", "InformationLevel", "Reserved", "FileName", "Pad1", "Data")),
        ByteField("Name", 0),
        StrFixedLenField("Pad", b"", length_from=lambda x:x.lengthfrom_Pad()),
        XLEShortField("InformationLevel", 0),
        LEIntField("Reserved", 0),
        SMBNullField("FileName", None),
        StrFixedLenField("Pad1", b"", length_from=lambda x:x.lengthfrom_Pad1()),
        PacketListField("Data", None, Packet),
    ]
    def lengthfrom_Pad(self):
        if self.underlayer.ParamOffset == 0:
            return 0
        pad = self.underlayer.ParamOffset - self.underlayer.size() 
        pad -= 32 # SMB header
        pad -= 2 # ByteCount in SMB Data
        pad -= 1 # Name in SMB Data
        return pad

    def lengthfrom_Pad1(self):
       if self.underlayer.DataOffset == 0:
           return 0
       pad = self.underlayer.DataOffset
       pad -= self.underlayer.ParamOffset
       pad -= self.underlayer.ParamCount
       return pad




class SMB_SET_FILE_BASIC_INFO_STRUCT(Packet):
    name = "SMB Set File Basic Info"
    infoLvl = SMB_SET_FILE_BASIC_INFO
    fields_desc = [
        LELongField("CreationTime", 0),
        LELongField("LastAccessTime", 0),
        LELongField("LastWriteTime", 0),
        LELongField("ChangeTime", 0),
        FlagsField("ExtFileAttributes", 0, -32, SMB_ExtFileAttributes),
        LEIntField("Reserved", 0),
    ]

class SMB_SET_FILE_DISPOSITION_INFO_STRUCT(Packet):
    name = "SMB Set File Disposition Info"
    infoLvl = SMB_SET_FILE_DISPOSITION_INFO
    fields_desc = [
        ByteField("DeletePending", 0),  # 0x01 = should be deleted
    ]

class SMB_SET_FILE_ALLOCATION_INFO_STRUCT(Packet):
    name = "SMB Set File Allocation Info"
    infoLvl = SMB_SET_FILE_ALLOCATION_INFO
    fields_desc = [
        LELongField("AllocationSize", 0),
    ]

class SMB_INFO_SET_EAS_STRUCT(Packet):
    name = "SMB Set File End Of File Info"
    infoLvl = SMB_SET_FILE_END_OF_FILE_INFO
    fields_desc = [
        LELongField("EndOfFile", 0),
    ]
 
 
class SMB_SET_FILE_END_OF_FILE_INFO_STRUCT(Packet):
    name = "SMB Set File End Of File Info"
    infoLvl = SMB_SET_FILE_END_OF_FILE_INFO
    fields_desc = [
        LELongField("EndOfFile", 0),
    ]
 
class SMB_STRUCT_INFO_STANDARD(Packet):
    name = "SMB Info Standard"
    fields_desc = [
        LEIntField("ResumeKey", 0),
        LEShortField("CreationDate", 0),
        LEShortField("CreationTime", 0),
        LEShortField("LastAccessDate", 0),
        LEShortField("LastAccessTime", 0),
        LEShortField("LastWriteDate", 0),
        LEShortField("LastWriteTime", 0),
        LEIntField("FileDataSize", 0),
        LEIntField("AllocationSize", 0),
        FlagsField("FileAttributes", 0, -16, SMB_FileAttributes),
        ByteField("FileNameLength", 0),
        StrField("FileName", None),
    ]

class SMB_STRUCT_INFO_QUERY_EA_SIZE(Packet):
    name = "SMB Info Query EA Size"
    fields_desc = [
        LEShortField("CreationDate", 0),
        LEShortField("CreationTime", 0),
        LEShortField("LastAccessDate", 0),
        LEShortField("LastAccessTime", 0),
        LEShortField("LastWriteDate", 0),
        LEShortField("LastWriteTime", 0),
        LEIntField("FileDataSize", 0),
        LEIntField("AllocationSize", 0),
        FlagsField("FileAttributes", 0, -16, SMB_FileAttributes),
        LEIntField("EaSize", None),
    ]


class SMB_STRUCT_QUERY_FILE_STANDARD_INFO(Packet):
    name = "SMB Query File Standard Info"
    fields_desc = [
        LELongField("AllocationSize", 0),
        LELongField("EndOfFile", 0),
        LEIntField("NumberOfLinks", 0),
        ByteField("DeletePending", 0),
        ByteField("Directory", 0),
        LEShortField("Reserved", 0),
    ]

class SMB_STRUCT_QUERY_FILE_BASIC_INFO(Packet):
    name = "SMB Query File Basic Info"
    fields_desc = [
        LELongField("CreationTime", 0),#363011174825242212),
        LELongField("LastAccessTime", 0),#363011174825242212),
        LELongField("LastWriteTime", 0),#363011174825242212),
        LELongField("LastChangeTime", 0),#363011174825242212),
        FlagsField("ExtFileAttributes", 0, -32, SMB_ExtFileAttributes),
        LEIntField("Reserved", 0),
    ]

class SMB_STRUCT_QUERY_FILE_EA_INFO(Packet):
    name = "SMB Query File EA Info"
    fields_desc = [
        LEIntField("EaSize", 0),
    ]

class SMB_STRUCT_QUERY_FILE_NAME_INFO(Packet):
    name = "SMB Query File EA Info"
    fields_desc = [
        FieldLenField("FileNameLength", None, length_of="FileName", fmt="<I"),
        StrField("FileName", None),
    ]


class SMB_STRUCT_QUERY_FILE_STREAM_INFO(Packet):
    name = "SMB Query File Stream Info"
    fields_desc = [
        LEIntField("NextEntryOffset", 0),
        FieldLenField("StreamNameLength", None, length_of="StreamName", fmt="<I"),
        LELongField("StreamSize", 0),
        LELongField("StreamAllocationSize", 0),
        StrLenField("StreamName", None),
    ]


class SMB_STRUCT_QUERY_FILE_COMPRESSION_INFO(Packet):
    name = "SMB Query File Compression Info"
    fields_desc = [
        LELongField("CompressedFileSize", 0),
        LEShortField("CompressionFormat", 0),
        ByteField("CompressionUnitShift", 0),
        ByteField("ChunkShift", 0),
        ByteField("ClusterShift", 0),
        ByteField("Reserved1", 0),
        ByteField("Reserved2", 0),
        ByteField("Reserved3", 0),
    ]

class SMB_STRUCT_QUERY_FILE_INTERNAL_INFO(Packet):
    name = "SMB Query File Internal Info"
    fields_desc = [
        LELongField("IndexNumber", 0x000b00000000b02a),
    ]



# page 45
class SMB_Trans2_Request(Packet):
    name = "SMB Trans2 Request"
    smb_cmd = SMB_COM_TRANSACTION2 # 0x32
    fields_desc = [
        ByteField("WordCount",15),
        LEShortField("TotalParamCount",0),
        LEShortField("TotalDataCount",0),
        LEShortField("MaxParamCount",0),
        LEShortField("MaxDataCount",0),
        ByteField("MaxSetupCount",0),
        ByteField("Reserved",0),
        XLEShortField("Flags",0),
        LEIntField("Timeout",0),
        ShortField("Reserved2",0),
        #FieldLenField("ParamCount", 0, fmt='<H', 1),#count_of="Param"),
        LEShortField("ParamCount", 0),#, fmt='<H', 1),#count_of="Param"),
        LEShortField("ParamOffset",0),
        LEShortField("DataCount",0),
        LEShortField("DataOffset",0),
        FieldLenField("SetupCount", 0, fmt='B', count_of="Setup"),
        ByteField("Reserved23",0),
        #        FieldListField("Setup", 0, ShortField("", 0), count_from = lambda pkt: pkt.SetupCount),
        FieldListField("Setup", 0, LEShortEnumField(
            "",0,SMB_Trans2_Commands), count_from = lambda pkt: pkt.SetupCount),
    ]


# TRANS2_QUERY_FILE_INFORMATION (0x0007)
# MS-CIFS p.418
class SMB_Trans2_QUERY_FILE_INFO_Request(Packet):
    name = "SMB Trans2 QUERY FILE INFO Request"
    fields_desc = [
        MultiFieldLenField("ByteCount", None, fmt='<H', length_of=("Name","Pad", "FID",  "InformationLevel", "Pad1", "GetEAList")),
        ByteField("Name", 0),
        StrFixedLenField("Pad", b"", length_from=lambda x:x.lengthfrom_Pad()),
        XLEShortField("FID", 0x4000),
        XLEShortField("InformationLevel", 0),
        StrFixedLenField("Pad1", b"", length_from=lambda x:x.lengthfrom_Pad1()),
        ConditionalField(StrLenField("GetEAList", b"", length_from=lambda x: x.underlayer.DataCount), lambda x:x.InformationLevel==SMB_INFO_QUERY_EAS_FROM_LIST)
    ]
    def lengthfrom_Pad(self):
        if self.underlayer.ParamOffset == 0:
            return 0
        pad = self.underlayer.ParamOffset - self.underlayer.size() 
        pad -= 32 # SMB header
        pad -= 2 # ByteCount in SMB Data
        pad -= 1 # Name in SMB Data
        return pad

    def lengthfrom_Pad1(self):
       if self.underlayer.DataOffset == 0:
           return 0
       pad = self.underlayer.DataOffset
       pad -= self.underlayer.ParamOffset
       pad -= self.underlayer.ParamCount
       return pad

class SMB_Trans2_QUERY_PATH_INFO_Request(Packet):
    name = "SMB Trans2 QUERY PATH INFO Request"
    fields_desc = [
        MultiFieldLenField("ByteCount", None, fmt='<H', length_of=("Name","Pad", "InformationLevel", "Reserved", "FileName", "Pad1", "GetEAList")),
        ByteField("Name", 0),
        StrFixedLenField("Pad", b"", length_from=lambda x:x.lengthfrom_Pad()),
        XLEShortField("InformationLevel", 0),
        LEIntField("Reserved", 0),
        StrField("FileName", 0),
        StrFixedLenField("Pad1", b"", length_from=lambda x:x.lengthfrom_Pad1()),
        ConditionalField(StrLenField("GetEAList", b"", length_from=lambda x: x.underlayer.DataCount), lambda x:x.InformationLevel==SMB_INFO_QUERY_EAS_FROM_LIST)
    ]
    def lengthfrom_Pad(self):
        if self.underlayer.ParamOffset == 0:
            return 0
        pad = self.underlayer.ParamOffset - self.underlayer.size() 
        pad -= 32 # SMB header
        pad -= 2 # ByteCount in SMB Data
        pad -= 1 # Name in SMB Data
        return pad

    def lengthfrom_Pad1(self):
       if self.underlayer.DataOffset == 0:
           return 0
       pad = self.underlayer.DataOffset
       pad -= self.underlayer.ParamOffset
       pad -= self.underlayer.ParamCount
       return pad



#
# MS-CIFS p.411
#
class SMB_Trans2_QUERY_FS_INFORMATION_Request(Packet):
    name = "SMB Trans2 QUERY FS INFORMATION Request"
    fields_desc = [
        MultiFieldLenField("ByteCount", None, fmt='<H', length_of=("Name","Pad", "InformationLevel", "Pad1")),
        ByteField("Name", 0),
        StrFixedLenField("Pad", b"", length_from=lambda x:x.lengthfrom_Pad()),
        #XLEShortField("InformationLevel", 0),
        LEShortEnumField("InformationLevel", 0, SMB_QueryFSInfoLvl),
        StrFixedLenField("Pad1", b"", length_from=lambda x:x.lengthfrom_Pad1()),
    ]
    def lengthfrom_Pad(self):
        if self.underlayer.ParamOffset == 0:
            return 0
        pad = self.underlayer.ParamOffset - self.underlayer.size() 
        pad -= 32 # SMB header
        pad -= 2 # ByteCount field in SMB Data
        pad -= 1 # Name field in SMB Data
        return pad

    def lengthfrom_Pad1(self):
       if self.underlayer.DataOffset == 0:
           return 0
       pad = self.underlayer.DataOffset
       pad -= self.underlayer.ParamOffset
       pad -= self.underlayer.ParamCount
       return pad 


# MS-CIFS p.403
#
class SMB_Trans2_FIND_FIRST2_Request(Packet):
    name = "SMB Trans2 FIND FIRST2 Request"
    smb_cmd = SMB_COM_TRANSACTION2
    fields_desc =[
        MultiFieldLenField("ByteCount", None, fmt='<H', length_of=("Name","Pad","SearchAttributes", "SearchCount", "Flags", "InformationLevel", "SearchStorageType", "FileName", "Pad1", "GetEAList")),
        ByteField("Name", 0),
        StrFixedLenField("Pad", b"", length_from=lambda x:x.lengthfrom_Pad()),
        FlagsField("SearchAttributes", 0, -16, SMB_SearchAttributes),
        LEShortField("SearchCount",0),
        FlagsField("Flags", 0, -16, SMB_Trans2_FIND_FIRST2_Flags),
        XLEShortField("InformationLevel", 0),
        LEIntField("SearchStorageType",0),
        StrFixedLenField("FileName", b"", length_from=lambda x: x.underlayer.ParamCount-12),
        StrFixedLenField("Pad1", b"", length_from=lambda x:x.lengthfrom_Pad1()),
        ConditionalField(StrLenField("GetEAList", b"", length_from=lambda x: x.underlayer.DataCount), lambda x:x.InformationLevel==SMB_INFO_QUERY_EAS_FROM_LIST)
    ]
    def lengthfrom_Pad(self):
        if self.underlayer.ParamOffset == 0:
            return 0
        pad = self.underlayer.ParamOffset - self.underlayer.size() 
        pad -= 32 # SMB header
        pad -= 2 # ByteCount in SMB Data
        pad -= 1 # Name in SMB Data
        return pad

    def lengthfrom_Pad1(self):
       if self.underlayer.DataOffset == 0:
           return 0
       pad = self.underlayer.DataOffset
       pad -= self.underlayer.ParamOffset
       pad -= self.underlayer.ParamCount
       return pad 



class SMB_Trans2_QUERY_INFO_Response_Param(Packet):
    name = "SMB Trans2 QUERY FILE INFO Response Param"
    fields_desc = [
        LEShortField("EaErrorOffset", 0),
    ]




class SMB_Trans2_QUERY_FS_INFO_Response_Param(Packet):
    name = "SMB Trans2 QUERY FILE INFO Response Param"
    fields_desc = [
    ]


class SMB_Trans2_FIND_FIRST2_Response_Param(Packet):
    name = "SMB Trans2 FIND FIRST2 Response Param"
    smb_cmd = SMB_COM_TRANSACTION2
    fields_desc = [
        LEShortField("SearchID",0xfffd),
        LEShortField("SearchCount",0),
        LEShortField("EndOfSearch",1),
        LEShortField("ErrorOffset",0),
        LEShortField("LastNameOffset",0),
]

class SMB_Trans2_Final_Response(Packet):
    name = "SMB Trans2 FIND FIRST2 Response"
    smb_cmd = SMB_COM_TRANSACTION2
    fields_desc = [
        #ByteField("WordCount",10),
        FieldLenField("WordCount", None, fmt="B", count_of="Setup", adjust=lambda pkt,x:x+10), 
        FieldLenField("TotalParamCount", None, fmt='<H', length_of="Param"),
        FieldLenField("TotalDataCount", None, fmt="<H", length_of="Data"), 
        LEShortField("Reserved1",0),
        FieldLenField("ParamCount", None, fmt='<H', length_of="Param"),
        FieldLenField("ParamOffset", None, fmt='<H', count_of="Setup", adjust=lambda pkt,x:pkt.calcParamOffset(x)),
        LEShortField("ParamDisplacement",0),
        FieldLenField("DataCount", None, fmt="<H", length_of="Data"), 
        FieldLenField("DataOffset", None, fmt="<H", length_of="Setup", adjust=lambda pkt,x:pkt.calcDataOffset(x)),
        LEShortField("DataDisplacement",0),
        FieldLenField("SetupCount", None, fmt="<B", count_of="Setup"), 
        #ByteField("SetupCount",1), 
        ByteField("Reserved2",0), 
        FieldListField("Setup", None, LEShortEnumField("", None, SMB_Trans2_Commands)),# count_from = lambda pkt: pkt.setup()),
        MultiFieldLenField("ByteCount", None, fmt='<H', length_of=("Pad1","Param","Pad2","Data")),
        StrFixedLenField("Pad1", None, length_from=lambda x:x.lengthfrom_Pad1()),
        PacketField("Param", None, Packet),
        StrFixedLenField("Pad2", None, length_from=lambda x:x.lengthfrom_Pad2()),
        PacketListField("Data", None, PacketField("", None, Packet)),
    ]


    def calcParamOffset(self, setupLen):
        offset = 55  # SMB header and fixed SMB param
        offset += setupLen*2  # setup len in byte
        # len pad1 should only depend on setup, before everything should be aligned
        offset += ((4-(3+2*setupLen)%4)%4)  
        return offset

    def calcDataOffset(self, setupLen):
        offset = 55+setupLen*2+((4-(3+2*setupLen)%4)%4) # param offset
        offset += len(self.Param) 
        offset += ((4-len(self.Param)%4)%4) # len pad2
        return offset

    # SMB header and parameter already aligned;wordcount,setupcount and bytecount are not
    def lengthfrom_Pad1(self):
        pad = (4 - (1 + 2*len(self.Setup) + 2) % 4) % 4
        return pad

    # trans2 paramoffset already aligned,thus pad only depends on paramcount
    def lengthfrom_Pad2(self):
        pad = (4 - len(self.Param) % 4) % 4
        return pad



class SMB_Trans2_Response(Packet):
    name = "SMB Trans2 Response"
    smb_cmd = SMB_COM_TRANSACTION2 #0x32
    fields_desc = [
        ByteField("WordCount",0),
        LEShortField("ByteCount",0),
    ]

class SMB_Trans2_Secondary_Request(Packet):
    name = "SMB Trans2 Secondary Request"
    smb_cmd = SMB_COM_TRANSACTION2_SECONDARY # 0x33
    fields_desc = [
        ByteField("WordCount",0),
        LEShortField("TotalParamCount",0),
        LEShortField("TotalDataCount",0),
        LEShortField("MaxParamCount",0),
        LEShortField("MaxDataCount",0),
        ByteField("MaxSetupCount",0),
        ByteField("Reserved",0),
        XLEShortField("Flags",0),
        LEIntField("Timeout",0),
        ShortField("Reserved2",0),
        FieldLenField("ParamCount", 0, fmt='<H', count_of="Data"),
        StrFixedLenField("Data", "", length_from=lambda pkt: pkt.ParamCount),
    ]

#
#   SMB COM NT TRANSACTION Command
#
NT_TRANSACT_CREATE              = 0x0001
NT_TRANSACT_IOCTL               = 0x0002
NT_TRANSACT_SET_SECURITY_DESC   = 0x0003
NT_TRANSACT_NOTIFY_CHANGE       = 0x0004
NT_TRANSACT_RENAME              = 0x0005
NT_TRANSACT_QUERY_SECURITY_DESC = 0x0006


class SMB_NT_Trans_Request(Packet):
    name = "SMB NT Trans Request"
    smb_cmd = SMB_COM_NT_TRANSACT #0xa0
    fields_desc = [
        ByteField("WordCount",0),
        ByteField("MaxSetupCount",0),
        ShortField("Reserved",0),
        LEIntField("TotalParamCount",0),
        LEIntField("TotalDataCount",0),
        LEIntField("MaxParamCount",0),
        LEIntField("MaxDataCount",0),
        FieldLenField("ParamCount", 0, fmt='<I', length_of="Param"),
        #LEIntField("ParamCount", 0),
        LEIntField("ParamOffset",0),
        LEIntField("DataCount",0),
        LEIntField("DataOffset",0),
        FieldLenField("SetupCount", 0, fmt='B', count_of="Setup", adjust = lambda pkt,x:x/2),
        LEShortField("Function",0),
        FieldListField("Setup", None, XByteField("", None), count_from = lambda pkt:pkt.SetupCount*2), 
        LEShortField("ByteCount", 0),
        # len pad1 = paramoffset - len SMB param - len(bytecount) - len(wordcount) - SMB header 
        StrLenField("Pad1", 0, length_from = lambda pkt:pkt.ParamOffset-pkt.WordCount*2-35),
        StrLenField("Param", 0, length_from=lambda pkt:pkt.ParamCount),
        StrLenField("Pad2", 0, length_from = lambda pkt:pkt.DataOffset-pkt.ParamOffset-pkt.ParamCount),
        StrLenField("Data", b"", length_from=lambda pkt: pkt.DataCount),
    ]

class SMB_NT_Trans_IOCTL_Request(Packet):
    name = "SMB NT Trans IOCTL Request"
    fields_desc = [
            ]

class SMB_NT_Trans_Response(Packet):
    name = "SMB NT Trans Response"
    smb_cmd = SMB_COM_NT_TRANSACT #0xa0
    fields_desc = [
        ByteField("WordCount",0),
        LEShortField("ByteCount",0),
    ]

class SMB_NT_Trans_Final_Response(Packet):
    name = "SMB NT Trans Final Response"
    smb_cmd = SMB_COM_NT_TRANSACT
    fields_desc = [
        FieldLenField("WordCount", None, fmt="B", count_of="Setup", adjust=lambda pkt,x:x+18), 
        StrFixedLenField("Reserved1", 0, length=3),
        FieldLenField("TotalParamCount", None, fmt='<I', length_of="Param"),
        FieldLenField("TotalDataCount", None, fmt="<I", length_of="Data"), 
        FieldLenField("ParamCount", None, fmt='<I', length_of="Param"),
        FieldLenField("ParamOffset", None, fmt='<I', length_of="Setup", adjust=lambda pkt,x:pkt.calcParamOffset(x)),
        LEIntField("ParamDisplacement",0),
        FieldLenField("DataCount", None, fmt="<I", length_of="Data"), 
        FieldLenField("DataOffset", None, fmt="<I", length_of="Setup", adjust=lambda pkt,x:pkt.calcDataOffset(x)),
        LEIntField("DataDisplacement",0),
        FieldLenField("SetupCount", None, fmt="<B", count_of="Setup"), 
        FieldListField("Setup", None, LEShortField("", None)),# count_from = lambda pkt: pkt.setup()),
        MultiFieldLenField("ByteCount", None, fmt='<H', length_of=("Pad1","Param","Pad2","Data")),
        StrLenField("Pad1", None, length_from=lambda x:x.lengthfrom_Pad1()),
        PacketLenField("Param", None, Packet),
        StrLenField("Pad2", None, length_from=lambda x:x.lengthfrom_Pad2()),
        StrLenField("Data", None),
    ]


    def calcParamOffset(self, setupLen):
        offset = 32 + 1 + 18*2 + 2 # SMB header and fixed SMB param
        offset += setupLen  # setup len in byte
        offset += ((4-offset)%4)%4 # pad1 
        return offset

    def calcDataOffset(self, setupLen):
        offset = 32 + 1 + 18*2 + 2 + setupLen
        offset += ((4-offset)%4)%4 # pad1 
        offset += len(self.Param) 
        offset += ((4-offset)%4)%4 # len pad2
        return offset

    # SMB header and parameter already aligned;wordcount,setupcount and bytecount are not
    def lengthfrom_Pad1(self):
        pad = (4 - (1 + 2*len(self.Setup) + 2) % 4) % 4
        return pad

    # trans2 paramoffset already aligned,thus pad only depends on paramcount
    def lengthfrom_Pad2(self):
        pad = (4 - len(self.Param) % 4) % 4
        return pad

class SMB_NT_Trans_IOCTL_Response_Param(Packet):
    name = "SMB NT Trans IOCTL Response Param"
    fields_desc = [

            ]



# [MS-CIFS].pdf - 2.2.5 Transaction Subcommands
# http://msdn.microsoft.com/en-us/library/ee441557%28v=PROT.13%29.aspx
TRANS_NMPIPE_SET_STATE        = 0x0001
TRANS_NMPIPE_RAW_READ        = 0x0011
TRANS_NMPIPE_QUERY_STATE    = 0x0021
TRANS_NMPIPE_QUERY_INFO        = 0x0022
TRANS_NMPIPE_PEEK            = 0x0023
TRANS_NMPIPE_TRANSACT        = 0x0026
TRANS_NMPIPE_RAW_WRITE        = 0x0031
TRANS_NMPIPE_READ            = 0x0036
TRANS_NMPIPE_WRITE            = 0x0037
TRANS_NMPIPE_WAIT            = 0x0053
TRANS_NMPIPE_CALL            = 0x0054
TRANS_MAILSLOT_WRITE        = 0x0001


# http://www.microsoft.com/about/legal/protocols/BSTD/CIFS/draft-leach-cifs-v1-spec-02.txt
# 5.8  OPEN_ANDX:  Open File

class SMB_Open_AndX_Request(Packet):
    name = "SMB Open AndX Request"
    fields_desc = [
        ByteField("WordCount",14),
        ByteEnumField("AndXCommand",0xff,SMB_Commands),
        ByteField("AndXReserved",0),
        LEShortField("AndXOffset",0),
        #        LEShortField("Flags",0), #
        FlagsField("Flags", 0, -16, SMB_CreateFlags),
        LEShortField("DesiredAcess",0),
        LEShortField("SearchAttributes",0),
        #        LEShortField("FileAttributes",0),
        FlagsField("FileAttributes", 0, -16, SMB_FileAttributes),
        #        NTTimeField("CreationTime",datetime.datetime.now()),
        LEIntField("CreationTime", 0),
        LEShortField("OpenFunction",0),
        LEIntField("AllocationSize",0),
        StrFixedLenField("Reserved", b"", length=8),
        LEShortField("ByteCount",0),
        ByteField("BufferFormat",0),
        SMBNullField("FileName",""),
    ]

class SMB_Open_AndX_Response(Packet):
    name = "SMB Open AndX Response"
    smb_cmd = SMB_COM_OPEN_ANDX #0x2d
    fields_desc = [
        ByteField("WordCount",15),
        ByteEnumField("AndXCommand",0xff,SMB_Commands),
        ByteField("AndXReserved",0),
        LEShortField("AndXOffset",0),
        LEShortField("FID",0),
        FlagsField("FileAttributes", 0, -16, SMB_FileAttributes),
        NTTimeField("LastWriteTime",datetime.datetime.now()),
        LEIntField("DataSize",0),
        LEShortField("GrantedAccess",0),
        LEShortField("FileType",0),
        LEShortField("DeviceState",0),
        LEIntField("ServerFID",0),
        LEShortField("Reserved",0),
        LEShortField("ByteCount",0),
    ]


# page 88
# request and response are identical
class SMB_Close(Packet):
    name = "SMB Close"
    smb_cmd = SMB_COM_CLOSE
    fields_desc = [
        ByteField("WordCount",3),
        XLEShortField("FID",0),
        LEIntField("LastWriteTime", 0),
        LEShortField("ByteCount",0),
    ]


class SMB_Close_Response(Packet):
    name = "SMB Close"
    smb_cmd = SMB_COM_CLOSE
    fields_desc = [
        ByteField("WordCount",0),
#        XLEShortField("FID",0),
#        LEIntField("LastWriteTime", 0),
        LEShortField("ByteCount",0),
    ]


# page 67
# request and response are identical
class SMB_Logoff_AndX(Packet):
    name = "SMB Logoff AndX"
    smb_cmd = SMB_COM_LOGOFF_ANDX
    fields_desc = [
        ByteField("WordCount",2),
        ByteEnumField("AndXCommand",0xff,SMB_Commands),
        ByteField("AndXReserved",0),
        LEShortField("AndXOffset", 0),
        LEShortField("ByteCount",0),
    ]

# page 75
# request and response are identical
class SMB_Echo(Packet):
    name = "SMB Echo"
    smb_cmd = SMB_COM_ECHO
    fields_desc = [
        ByteField("WordCount",1),
        LEShortField("EchoCount", 0),
        FieldLenField("ByteCount", 1, fmt='<H', length_of="Buffer"),
        StrLenField("Buffer", b"\xff", length_from=lambda x:x.ByteCount),
    ]

# page 89
class SMB_Delete_Request(Packet):
    name = "SMB Delete Request"
    smb_cmd = SMB_COM_DELETE #0x06
    fields_desc = [
        ByteField("WordCount",1),
        FlagsField("SearchAttributes", 0, -16, SMB_FileAttributes),
        FieldLenField("ByteCount", 1, fmt='<H', length_of="FileName"),
        ByteField("BufferFormat",4),
        StrLenField("FileName", None, length_from=lambda x:x.ByteCount-1),
    ]

class SMB_Delete_Response(Packet):
    name = "SMB Delete Response"
    smb_cmd = SMB_COM_DELETE
    fields_desc = [
        ByteField("WordCount",0),
        LEShortField("ByteCount",0),
    ]

class SMB_Delete_Directory_Request(Packet):
    name = "SMB Delete Request"
    smb_cmd = SMB_COM_DELETE #0x06
    fields_desc = [
        ByteField("WordCount",1),
        FieldLenField("ByteCount", 1, fmt='<H', length_of="FileName"),
        ByteField("BufferFormat",4),
        StrLenField("DirName", None, length_from=lambda x:x.ByteCount-1),
    ]

class DCERPC_Header(Packet):
    name = "DCERPC Header"
    fields_desc = [
        ByteField("Version",5),
        ByteField("VersionMinor",0),
        ByteEnumField("PacketType",0,DCERPC_PacketTypes),
        XByteField("PacketFlags",0x3),
        LEIntField("DataRepresentation",16),
        LEShortField("FragLen",0),
        LEShortField("AuthLen",0),
        LEIntField("CallID",0),
    ]

class DCERPC_Request(Packet):
    name = "DCERPC Request"
    fields_desc = [
        FieldLenField("AllocHint", 14, fmt='<I', length_of="StubData"),
        LEShortField("ContextID",0),
        LEShortField("OpNum",0),
        StrLenField("StubData", "", length_from=lambda x:x.AllocHint),
    ]

class DCERPC_Response(Packet):
    name = "DCERPC Response"
    fields_desc = [
        FieldLenField("AllocHint", 0, fmt='<I', length_of="StubData"),
        LEShortField("ContextID",0),
        ByteField("CancelCount",0),
        StrLenField("Pad", "\0"),
        StrLenField("StubData", ""),
    ]

class DCERPC_CtxItem(Packet):
    name = "DCERPC CtxItem"
    fields_desc = [
        LEShortField("ContextID",0),
        FieldLenField('NumTransItems', 1, fmt='B', length_of="TransItems"),
        ByteField("FixGap", 0),
        #        StrLenField('UUID', '', length_from = lambda x: 16),
        UUIDField('UUID', ''),
        LEShortField("InterfaceVer",0),
        LEShortField("InterfaceVerMinor",0),
        #        StrFixedLenField('TransferSyntax', '', 16),
        UUIDField('TransferSyntax', ''),
        LEIntField('TransferSyntaxVersion', 0)
    ]

class DCERPC_Bind(Packet):
    name = "DCERPC Bind"
    fields_desc = [
        LEShortField("MaxTransmitFrag",5840),
        LEShortField("MaxReceiveFrag",5840),
        XLEIntField("AssocGroup",0),
        #        ByteField("NumCtxItems",1),
        #        PacketLenField("NumCtxItems", 1, None, length_from),
        FieldLenField("NumCtxItems", 0, fmt='B', count_of="CtxItems"),
        StrLenField("FixGap", "\0"*3, length_from=lambda x:3),
        PacketListField(
            "CtxItems", None, DCERPC_CtxItem, count_from=lambda pkt:pkt.NumCtxItems)
    ]

class DCERPC_Ack_CtxItem(Packet):
    name = "DCERPC Ack CtxItem"
    fields_desc = [
        LEShortField("AckResult",2),
        LEShortField("AckReason",1),
        #Field("TransferSyntax","\0"*16, fmt="QQ"),
        #        StrFixedLenField('TransferSyntax', '', 16),
        UUIDField("TransferSyntax", ""),
        LEIntField('TransferSyntaxVersion', 0)
    ]


class DCERPC_Auth_Verfier(Packet):
    """http://www.opengroup.org/onlinepubs/9629399/chap13.htm#tagcjh_18"""
    name = "DCERPC Auth Verifier"
    fields_desc = [
        #        StrFixedLenField("Pad", "", 5),
        ByteField("Type", 0),
        ByteField("Level", 0),
        ByteField("PadLength", 0),
        ByteField("Reserved", 0),
        XIntField("ContextID", 0),
    ]

class DCERPC_Bind_Ack(Packet):
    name = "DCERPC Bind Ack"
    fields_desc = [
        LEShortField("MaxTransmitFrag",4280),
        LEShortField("MaxReceiveFrag",4280),
        XLEIntField("AssocGroup",0x4ef7),
        FieldLenField("SecondAddrLen", 14, fmt='<H', length_of="SecondAddr"),
        StrLenField(
            "SecondAddr", "\\PIPE\\browser\0", length_from=lambda x:x.SecondAddrLen),
        #        ByteField("NumCtxItems",1),
        FieldLenField("NumCtxItems", 0, fmt='B', count_of="CtxItems"),
        StrLenField("FixGap", "\0"*3, length_from=lambda x:3),
        PacketListField(
            "CtxItems", 0, DCERPC_Ack_CtxItem, count_from=lambda pkt:pkt.NumCtxItems)
    ]

RAP_OP_NETSHAREENUM = 0x00

RAP_Opcodes = {
    RAP_OP_NETSHAREENUM : "NetShareEnum"
}

class RAP_Request(Packet):
    name = "RAP Request"
    fields_desc = [
        LEShortEnumField("Opcode",RAP_OP_NETSHAREENUM,RAP_Opcodes),
        StrNullField("ParamDesc",""),
        StrNullField("DataDesc", ""),
        StrLenField(
            "Params", "", length_from=lambda x: x.length_of_RAPParams()),
        StrNullField("AuxDesc", ""),
    ]
    def length_of_RAPParams(self):
        if self.Opcode == 0x0000:
            return 4
        return 0

# from dionaea.smb.include.smbfields import *
class RAP_Response(Packet):
    name = "RAP Response"
    fields_desc = [
        LEShortField("Win32ErrorCode", 0),
        LEShortField("Converter",0),
        StrField("OutParams",""),
        StrField("OutData","")
    ]

class WKSTA_INFO_100(Packet):
    name = "Workstation Info 100"
    fields_desc = [
        LEIntField("wki100_platform_id", 500),
        StrNullField("wki100_computername", "WORKSTATION"),
        StrNullField("wki100_langroup", "WORKGROUP"),
        LEIntField("wki100_ver_major", 5),
        LEIntField("wki100_ver_minor", 1),
        LEIntField("ReturnCode", 0)
    ]




bind_bottom_up(NBTSession, NBTSession_Request, TYPE = lambda x: x==0x81)
bind_bottom_up(NBTSession, SMB_Header, TYPE = lambda x: x==0)
bind_bottom_up(SMB_Header, SMB_Negociate_Protocol_Response,
               Command=lambda x: x==0x72, Flags=lambda x: x&0x80)
bind_bottom_up(SMB_Header, SMB_Negociate_Protocol_Request_Counts,
               Command=lambda x: x==0x72, Flags=lambda x: not x&0x80)
#bind_bottom_up(SMB_Header, SMB_Sessionsetup_AndX_Request, Command=lambda x: x==0x73, Flags=lambda x: not x&0x80, Flags2=lambda x: not x&2)
bind_bottom_up(SMB_Header, SMB_Sessionsetup_AndX_Request2, Command=lambda x: x==
               0x73, Flags=lambda x: not x&0x80, Flags2=lambda x: not x&SMB_FLAGS2_EXT_SEC)
bind_bottom_up(SMB_Header, SMB_Sessionsetup_ESEC_AndX_Request, Command=lambda x:
               x==0x73, Flags=lambda x: not x&0x80, Flags2=lambda x: x&SMB_FLAGS2_EXT_SEC)
#bind_bottom_up(SMB_Header, SMB_Sessionsetup_AndX_Response2, Command=lambda x: x==0x73, Flags=lambda x: x&0x80)
bind_bottom_up(SMB_Header, SMB_Treedisconnect, Command=lambda x: x==0x71)
bind_bottom_up(SMB_Header, SMB_Treeconnect_AndX_Request,
               Command=lambda x: x==0x75, Flags=lambda x: not x&0x80)
bind_bottom_up(SMB_Header, SMB_Treeconnect_AndX_Response,
               Command=lambda x: x==0x75, Flags=lambda x: x&0x80)
bind_bottom_up(SMB_Header, SMB_Treeconnect_AndX_Response2,
               Command=lambda x: x==0x75, Flags=lambda x: x&0x80)
#bind_bottom_up(SMB_Header, SMB_Treeconnect_AndX_Response_Extended, Command=lambda x: x==0x75, Flags=lambda x: x&0x80)
bind_bottom_up(SMB_Header, SMB_NTcreate_AndX_Request,
               Command=lambda x: x==0xa2, Flags=lambda x: not x&0x80)
bind_bottom_up(SMB_Header, SMB_NTcreate_AndX_Response_ERROR,
               Command=lambda x: x==0xa2, Flags=lambda x: x&0x80)
bind_bottom_up(SMB_Header, SMB_NTcreate_AndX_Response,
               Command=lambda x: x==0xa2, Flags=lambda x: x&0x80)
bind_bottom_up(SMB_Header, SMB_Trans_Request,
               Command=lambda x: x==0x25, Flags=lambda x: not x&0x80)
bind_bottom_up(SMB_Header, SMB_Trans2_Request,
               Command=lambda x: x==0x32, Flags=lambda x: not x&0x80)
bind_bottom_up(SMB_Header, SMB_Trans2_Secondary_Request, Command=lambda x: x==0x33, Flags=lambda x: not x&0x80)

bind_bottom_up(SMB_Header, SMB_Write_AndX_Request,
               Command=lambda x: x==0x2f, Flags=lambda x: not x&0x80)
bind_bottom_up(SMB_Header, SMB_Write_AndX_Response,
               Command=lambda x: x==0x2f, Flags=lambda x: x&0x80)
bind_bottom_up(SMB_Header, SMB_Write_Request,
               Command=lambda x: x==SMB_COM_WRITE, Flags=lambda x: not x&0x80)
bind_bottom_up(SMB_Header, SMB_Write_Response,
               Command=lambda x: x==SMB_COM_WRITE, Flags=lambda x: x&0x80)

bind_bottom_up(SMB_Header, SMB_Read_AndX_Request,
               Command=lambda x: x==0x2e, Flags=lambda x: not x&0x80)
bind_bottom_up(SMB_Header, SMB_Read_AndX_Response,
               Command=lambda x: x==0x2e, Flags=lambda x: x&0x80)

bind_bottom_up(SMB_Header, SMB_Open_AndX_Request,
               Command=lambda x: x==0x2d, Flags=lambda x: not x&0x80)

bind_bottom_up(SMB_Header, SMB_Close, Command=lambda x: x==SMB_COM_CLOSE)
bind_bottom_up(
    SMB_Header, SMB_Logoff_AndX, Command=lambda x: x==SMB_COM_LOGOFF_ANDX)
bind_bottom_up(SMB_Header, SMB_Echo, Command=lambda x: x==SMB_COM_ECHO)
bind_bottom_up(SMB_Header, SMB_Delete_Request,
               Command=lambda x: x==SMB_COM_DELETE, Flags=lambda x: not x&0x80)

#bind_bottom_up(SMB_Write_AndX_Request, SMB_Data)
bind_bottom_up(SMB_Read_AndX_Response, SMB_Data)
bind_bottom_up(SMB_Header, SMB_NT_Trans_Request, Command=lambda x:x==SMB_COM_NT_TRANSACT) 

bind_bottom_up(SMB_Header, SMB_Rename_Request, Command=lambda x:x==SMB_COM_RENAME) 
bind_bottom_up(SMB_Header, SMB_Delete_Directory_Request, Command=lambda x:x==SMB_COM_DELETE_DIRECTORY) 

# dissect trans2 requests based on trans2 subcom code in SMB parameter setup field
bind_bottom_up(SMB_Trans2_Request, SMB_Trans2_FIND_FIRST2_Request, Setup=lambda x:x==[SMB_TRANS2_FIND_FIRST2])
bind_bottom_up(SMB_Trans2_Request, SMB_Trans2_QUERY_FILE_INFO_Request, Setup=lambda x:x==[SMB_TRANS2_QUERY_FILE_INFORMATION])
bind_bottom_up(SMB_Trans2_Request, SMB_Trans2_QUERY_PATH_INFO_Request, Setup=lambda x:x==[SMB_TRANS2_QUERY_PATH_INFORMATION])
bind_bottom_up(SMB_Trans2_Request, SMB_Trans2_QUERY_FS_INFORMATION_Request, Setup=lambda x:x==[SMB_TRANS2_QUERY_FS_INFORMATION])
bind_bottom_up(SMB_Trans2_Request, SMB_Trans2_SET_FILE_INFO_Request, Setup=lambda x:x==[SMB_TRANS2_SET_FILE_INFORMATION])
bind_bottom_up(SMB_Trans2_SET_FILE_INFO_Request, SMB_SET_FILE_BASIC_INFO_STRUCT, InformationLevel=lambda x:x==SMB_SET_FILE_BASIC_INFO)
bind_bottom_up(SMB_Trans2_SET_FILE_INFO_Request, SMB_SET_FILE_DISPOSITION_INFO_STRUCT, InformationLevel=lambda x:x==SMB_SET_FILE_DISPOSITION_INFO or x==1013)
bind_bottom_up(SMB_Trans2_SET_FILE_INFO_Request, SMB_SET_FILE_ALLOCATION_INFO_STRUCT, InformationLevel=lambda x:x==SMB_SET_FILE_ALLOCATION_INFO or x==1019)
bind_bottom_up(SMB_Trans2_SET_FILE_INFO_Request, SMB_SET_FILE_END_OF_FILE_INFO_STRUCT, InformationLevel=lambda x:x==SMB_SET_FILE_END_OF_FILE_INFO or x==1020)

bind_bottom_up(SMB_Trans_Request, DCERPC_Header)
bind_bottom_up(DCERPC_Header, DCERPC_Request, PacketType=lambda x: x==0)
bind_bottom_up(DCERPC_Header, DCERPC_Bind, PacketType=lambda x: x==11)
bind_bottom_up(DCERPC_Header, DCERPC_Bind_Ack, PacketType=lambda x: x==12)
#bind_bottom_up(DCERPC_Bind, DCERPC_CtxItem)
#bind_bottom_up(DCERPC_CtxItem, DCERPC_CtxItem)

#bind_bottom_up(SMB_Sessionsetup_AndX_Request, SMB_Treeconnect_AndX_Request, AndXCommand=lambda x: x==0x75)
bind_bottom_up(SMB_Sessionsetup_AndX_Request2,
               SMB_Treeconnect_AndX_Request, AndXCommand=lambda x: x==0x75)
#bind_bottom_up(SMB_Negociate_Protocol_Request_Counts, SMB_Negociate_Protocol_Request_Tail)
#bind_bottom_up(SMB_Negociate_Protocol_Request_Tail, SMB_Negociate_Protocol_Request_Tail)
bind_bottom_up(SMB_Header, SMB_Parameters)
bind_bottom_up(SMB_Parameters, SMB_Data)

bind_top_down(SMB_Header, SMB_Negociate_Protocol_Response, Command=0x72)
bind_top_down(SMB_Header, SMB_Sessionsetup_AndX_Response2, Command=0x73)
bind_top_down(SMB_Header, SMB_Sessionsetup_ESEC_AndX_Response, Command=0x73)
bind_top_down(SMB_Header, SMB_Treeconnect_AndX_Response, Command=0x75)
bind_top_down(SMB_Header, SMB_Treeconnect_AndX_Response2, Command=0x75)
#bind_top_down(SMB_Header, SMB_Treeconnect_AndX_Response_Extended, Command=0x75)
bind_top_down(SMB_Header, SMB_Treedisconnect, Command=0x71)
bind_top_down(SMB_Header, SMB_NTcreate_AndX_Response, Command=0xa2)
bind_top_down(SMB_Header, SMB_NTcreate_AndX_Response_ERROR, Command=0xa2)
bind_top_down(SMB_Header, SMB_Write_AndX_Response, Command=0x2f)
bind_top_down(SMB_Header, SMB_Write_Response, Command=SMB_COM_WRITE)
bind_top_down(SMB_Header, SMB_Read_AndX_Response, Command=0x2e)
bind_top_down(SMB_Header, SMB_Trans_Request, Command=0x25)
bind_top_down(SMB_Header, SMB_Trans2_Request, Command=0x32)
bind_top_down(SMB_Header, SMB_Trans2_Secondary_Request, Command=0x33)
bind_top_down(SMB_Header, SMB_Open_AndX_Request, Command=0x2d)
bind_top_down(SMB_Read_AndX_Response, SMB_Data)
#bind_top_down(SMB_Trans2_Final_Response, SMB_Trans2_FIND_FIRST2_Response, {ParamCount: length_of(self.))

bind_top_down(DCERPC_Header, DCERPC_Request, PacketType=0)
bind_top_down(DCERPC_Header, DCERPC_Response, PacketType=2)
bind_top_down(DCERPC_Header, DCERPC_Bind, PacketType=11)
bind_top_down(DCERPC_Header, DCERPC_Bind_Ack, PacketType=12)
#bind_bottom_up(DCERPC_Auth_Verfier, NTLMSSP_Header, Type=lambda x: x==10)
