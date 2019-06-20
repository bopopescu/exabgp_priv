"""
bgpsec.py

Created by Kyehwan Lee on 2018-01-19.
Copyright NIST. All rights reserved.
"""


from exabgp.bgp.message.update.attribute.attribute import Attribute
from struct import pack
#from exabgp.cryptobgpsec import *
from exabgp import cryptobgpsec
#import ctypes
#from struct import unpack

class BGPSEC (Attribute):
    ID = Attribute.CODE.BGPSEC
    FLAG = Attribute.Flag.OPTIONAL | Attribute.Flag.EXTENDED_LENGTH

    PCOUNT  = 0x01
    SP_FLAG = 0x00 # secure path segment flag
    ALGO_ID = 0x01
    #SKI     = 'C30433FA1975FF193181458FB902B501EA9789DC'
    #SKI     = '492AAE72485D926CACDA2D259BE19DAE82DFBDE3'
    #TEMP_SIG = "30 46 02 21 00 d5 e6 98 23 2a c6 ba b3 cf 23 30 b3 1e 0a 03 72 99 c6 14 13 55 fd 45 9d 3c 96 73 e4 c9 a0 14 ec 02 21 00 e1 03 f0 74 14 f3 ef 80 ca 99 15 10 3d df 0b 39 a7 45 cf eb 70 2f c5 13 39 45 7e cd f5 65 4d 4e"
    SIG_LEN = 2
    SKI_LEN = 20
    SEC_PATH_LEN = 2
    SIG_BLOCK_LEN = 2

    secure_path = []
    signature_block = []
    secure_path_segment = []
    signature_segment = []
    signature  = []
    secure_path_len = 0
    signature_block_len = 0

    init_lib = 0
    ski_str =''

    def __init__ (self, negotiated, nlri={}, packed=None):
        self.negotiated = negotiated
        self.packed = packed
        if nlri:
            self.nlri_ip = nlri[(1,1)][0].ip
            self.nlri_mask = nlri[(1,1)][0].mask

        self.crtbgp = cryptobgpsec.CryptoBgpsec()

    def _secure_path_segment (self, negotiated):
        segment = []
        segment.append(pack('!B', self.PCOUNT))
        segment.append(pack('!B', self.SP_FLAG))
        segment.append(pack('!L', self.negotiated.local_as))
        self.secure_path_len += 6   # secure path attribute (6)
        return segment


    def _secure_path (self, negotiated):
        self.secure_path = self._secure_path_segment(negotiated)
        return "%s%s" % (pack('!H', (self.secure_path_len+self.SEC_PATH_LEN)), ''.join(self.secure_path))


    def _signature_from_lib (self):
        if BGPSEC.init_lib != 1:
            self.crtbgp.crypto_init("PRIV:/users/kyehwanl/proj-bgp/extras/srxcryptoapi/keys/priv-ski-list.txt", 7)
            BGPSEC.init_lib = 1


        ret_sig = self.crtbgp.crypto_sign(self.negotiated.local_as, self.negotiated.peer_as, self.nlri_ip, self.nlri_mask, self.ski_str)
        return ret_sig



    def _signature (self):
        signature = []

        #step = 3
        #splitTEMP_SIG = [self.TEMP_SIG[i:i+step-1] for i in range(0, len(self.TEMP_SIG), step)]
        #signature = [ chr(int(splitTEMP_SIG[i], 16)) for i in range (0, len(splitTEMP_SIG))]

        signature = self._signature_from_lib()
        self.signature_block_len += len(signature)
        return "%s%s" % ( pack('!H', len(signature)), ''.join(signature))


    def _signature_segment (self):
        sig_segment = []
        # split SKI string into 2 letters
        step = 2
        self.ski_str = self.negotiated.neighbor.ski[0]
        splitSKI = [self.ski_str[i:i+step] for i in range(0, len(self.ski_str), step) ]
        #splitSKI = [self.SKI[i:i+step] for i in range(0, len(self.SKI), step) ]

        # convert hexstring into integer
        result = [ chr( int(splitSKI[i], 16)) for i in range (0, len(splitSKI))]
        sig_segment.extend(result)

        # processing signatures
        sig_segment.append(self._signature())
        self.signature_block_len += self.SIG_LEN + self.SKI_LEN
        return sig_segment


    def _signature_block (self, negotiated):
        sig_block = list()
        sig_block.append(pack('!B', self.ALGO_ID))
        self.signature_block_len += len(chr(self.ALGO_ID))
        self.signature_segment = self._signature_segment()
        sig_block.extend(self.signature_segment)
        return sig_block


    def _signature_blocks (self, negotiated):
        self.signature_block = self._signature_block(negotiated)
        return "%s%s" % ( pack('!H', (self.signature_block_len+self.SIG_BLOCK_LEN)), ''.join(self.signature_block))


    def bgpsec_pack (self, negotiated):
        # Secure Path & Signature Block needed from here
        # extract the proper information from 'negotiated' variable
        self.secure_path_len = 0
        self.signature_block_len = 0

        bgpsec_attr = self._secure_path(negotiated) + self._signature_blocks(negotiated)
        self.packed = bgpsec_attr = self._attribute(bgpsec_attr)
        return self.packed

    def pack (self, negotiated=None):
        if negotiated:
            return self.bgpsec_pack(negotiated)





"""
    +-----------------------------------------------+
    | Secure_Path Length                 (2 octets) |
    +-----------------------------------------------+
    | One or more Secure_Path Segments   (variable) |
    +-----------------------------------------------+
    Figure 4: Secure_Path Format


    +------------------------------------------------------+
    | pCount         (1 octet)                             |
    +------------------------------------------------------+
    | Confed_Segment flag (1 bit) |  Unassigned (7 bits)   | (Flags)
    +------------------------------------------------------+
    | AS Number      (4 octets)                            |
    +------------------------------------------------------+
    Figure 5: Secure_Path Segment Format


    +---------------------------------------------+
    | Signature_Block Length         (2 octets)   |
    +---------------------------------------------+
    | Algorithm Suite Identifier     (1 octet)    |
    +---------------------------------------------+
    | Sequence of Signature Segments (variable)   |
    +---------------------------------------------+
    Figure 6: Signature_Block Format


    +---------------------------------------------+
    | Subject Key Identifier (SKI)  (20 octets)   |
    +---------------------------------------------+
    | Signature Length              (2 octets)    |
    +---------------------------------------------+
    | Signature                     (variable)    |
    +---------------------------------------------+
    Figure 7: Signature Segment Format

"""
