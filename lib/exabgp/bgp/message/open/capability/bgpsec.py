# encoding: utf-8
"""
bgpsec.py

Created by Kyehwan Lee on 2018-01-05.
ANTD NIST
"""

#from struct import pack
#from struct import unpack
from exabgp.bgp.message.open.capability.capability import Capability

# =========================================================== BGPSEC open
# RFC 8205
"""
        0   1   2   3      4      5   6   7
        +---------------------------------------+
        | Version          | Dir |  Unassigned  |
        +---------------------------------------+
        |                                       |
        +------           AFI              -----+
        |                                       |
        +---------------------------------------+
"""

class BGPSEC (Capability, dict):

    ID = Capability.CODE.BGPSEC

    def __str__ (self):
        return "BGPSEC OPEN"

    def extract (self):
        rs = ['\x08\x00\x01',
              '\x00\x00\x01' ]
        return rs
        #return ["%s%s%s" % pack('!BBB',self)]

    @staticmethod
    def unpack_capability (instance, data, capability=None):  # pylint: disable=W0613
        return instance


