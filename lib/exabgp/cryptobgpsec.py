
"""
cryptobgpsec.py

Created by Kyehwan Lee on 2018-01-19.
Copyright NIST. All rights reserved.
"""

import ctypes
import os
import socket
import struct

#_file0 = './libSRxCryptoAPI.so'
#_mod0 = ctypes.cdll.LoadLibrary(_file0)

"""
 in Makefile of libSRxBGPSecOpenSSL.so, -L$(libdir) should be added for shared library dependencies
 otherwise, it happens 'OSError undefined symbol'
"""

bgpopenssl_file     = '/users/kyehwanl/Quagga_test/Proces_Performance/QuaggaSRxSuite/_inst/lib/srx/libSRxBGPSecOpenSSL.so'
#srxcryptoapi_file   = '/opt/project/srx_test1/api/.libs/libSRxCryptoAPI.so'
_path = os.path.join(*(os.path.split(__file__)[:-1] + (bgpopenssl_file,)))

bgpopenssl = ctypes.cdll.LoadLibrary(_path)
#srxcryptoapi = ctypes.cdll.LoadLibrary(srxcryptoapi_file)




class SCA_BGPSEC_SecurePathSegment (ctypes.Structure) :
    _pack_  = 1
    _fields_ = [('pCount', ctypes.c_uint8),
                ('flags',  ctypes.c_uint8),
                ('asn',     ctypes.c_uint32)]



class ADDR (ctypes.Union):
    _fields_ = [ ('ipV4',   ctypes.c_uint32),
                 ('ipV6',   ctypes.c_uint8 * 8),
                 ('ip',     ctypes.c_uint8 * 16)]

class SCA_Prefix (ctypes.Structure):
    _pack_  = 1
    _fields_ = [('afi',     ctypes.c_uint16),
                ('safi',    ctypes.c_uint8),
                ('length',  ctypes.c_uint8),
                ('addr',    ADDR)]

class SCA_HashMessagePtr (ctypes.Structure):
    _fields_ = [('signaturePtr', ctypes.POINTER(ctypes.c_uint8)),
                ('hashMessagePtr', ctypes.POINTER(ctypes.c_uint8)),
                ('hashMessageLength', ctypes.c_uint16)]

class SCA_HashMessage (ctypes.Structure):
    _fields_ = [('ownedByAPI',  ctypes.c_bool),
                ('bufferSize',  ctypes.c_uint32),
                ('buffer',      ctypes.POINTER(ctypes.c_uint8)),
                ('segmentCount', ctypes.c_uint16),
                ('hashMessageValPtr', ctypes.POINTER(ctypes.POINTER(SCA_HashMessagePtr)))]

class SCA_Signature(ctypes.Structure):
    _fields_ = [('ownedByAPI', ctypes.c_bool),
                ('algoID',  ctypes.c_uint8),
                ('ski',     ctypes.c_uint8 * 20),
                ('sigLen',  ctypes.c_uint16),
                ('sigBuff', ctypes.POINTER(ctypes.c_uint8))]


# structure SCA_BGPSecSignData {}
class SCA_BGPSecSignData(ctypes.Structure):
    #_pack_  = 1
    _fields_ = [('peerAS',      ctypes.c_uint32),
                ('myHost',      ctypes.POINTER(SCA_BGPSEC_SecurePathSegment)),
                ('nlri',        ctypes.POINTER(SCA_Prefix)),
                ('myASN',       ctypes.c_uint32),
                #('ski',         ctypes.POINTER(ctypes.c_uint8 * 20)),
                ('ski',         ctypes.c_char_p),
                ('algorithmID', ctypes.c_uint8),
                ('status',      ctypes.c_uint32),
                ('hashMessage', ctypes.POINTER(SCA_HashMessage)),
                ('signature',   ctypes.POINTER(SCA_Signature))]

# int sign(int count, SCA_BGPSecSignData** bgpsec_data)
sign = bgpopenssl.sign
sign.argtypes = (ctypes.c_int, ctypes.POINTER(ctypes.POINTER(SCA_BGPSecSignData)))
sign.restype = ctypes.c_int


# int _sign(SCA_BGPSecSignData* bgpsec_data)
_sign = bgpopenssl._sign
_sign.argtypes = ctypes.POINTER(SCA_BGPSecSignData),
_sign.restype = ctypes.c_int

# int init(const char* value, int debugLevel, sca_status_t* status);
init = bgpopenssl.init
init.argtypes = (ctypes.POINTER(ctypes.c_char), ctypes.c_int, ctypes.POINTER(ctypes.c_uint32))
init.restype = ctypes.c_int

# sca_SetKeyPath needed in libSRxCryptoAPI.so
# int sca_SetKeyPath (char* key_path)
#       sca_SetKeyPath((char *)key_volt);
# key_volt = "/opt/project/srx_test1/keys/";

#setKeyPath = srxcryptoapi.sca_SetKeyPath
#setKeyPath.argtypes = (ctypes.POINTER(ctypes.c_char),)
#setKeyPath.restype = ctypes.c_int


class CryptoBgpsec() :

    _BUFF_SIZE = 100
    _ALGO_ID = 1
    _PCOUNT = 1
    _FLAGS = 0

    def __init__ (self, negotiated=None):
        self.negotiated = negotiated
        self.crypto_init_value_type = ctypes.c_char_p

        if negotiated != None :
            self.bgpsec_openssl_lib = self.negotiated.neighbor.bgpsec_openssl_lib[0]
        else :
            self.bgpsec_openssl_lib = '/users/kyehwanl/Quagga_test/Proces_Performance/QuaggaSRxSuite/_inst/lib/srx/libSRxBGPSecOpenSSL.so'
        self._path = os.path.join(*(os.path.split(__file__)[:-1] + (self.bgpsec_openssl_lib,)))
        self.bgpsec_openssl = ctypes.cdll.LoadLibrary(self._path)


        # int sign(int count, SCA_BGPSecSignData** bgpsec_data)
        self.sign = self.bgpsec_openssl.sign
        self.sign.argtypes = (ctypes.c_int, ctypes.POINTER(ctypes.POINTER(SCA_BGPSecSignData)))
        self.sign.restype = ctypes.c_int


        # int _sign(SCA_BGPSecSignData* bgpsec_data)
        self._sign = self.bgpsec_openssl._sign
        self._sign.argtypes = ctypes.POINTER(SCA_BGPSecSignData),
        self._sign.restype = ctypes.c_int

        # int init(const char* value, int debugLevel, sca_status_t* status);
        self.init = self.bgpsec_openssl.init
        self.init.argtypes = (ctypes.POINTER(ctypes.c_char), ctypes.c_int, ctypes.POINTER(ctypes.c_uint32))
        self.init.restype = ctypes.c_int

    def crypto_init (self, init_str, debug_type):
        ret_init_value = self.crypto_init_value_type(init_str)
        initReturnVal = ctypes.c_uint32()

        # call API's init function
        self.init(ret_init_value, debug_type, initReturnVal)
        #return initReturnVal


    def crypto_sign (self, host_asn, peer_asn, prefix_str, nlri_mask, ski_data ) :

        host = SCA_BGPSEC_SecurePathSegment()
        host.pCount = 1
        host.flags = 0
        host.asn = socket.htonl(host_asn)

        addr = ADDR()
        addr.ipV4 = socket.htonl(struct.unpack("!L", socket.inet_aton(prefix_str))[0])

        nlri = SCA_Prefix()
        nlri.afi = socket.htons(1)
        nlri.safi = 1
        nlri.length = nlri_mask
        nlri.addr = addr

        ski_type = ctypes.c_char_p

        bgpsec_data = SCA_BGPSecSignData()
        bgpsec_data.peerAS = socket.htonl(peer_asn)
        bgpsec_data.myHost = ctypes.pointer(host)
        bgpsec_data.nlri = ctypes.pointer(nlri)
        bgpsec_data.myASN = socket.htonl(host_asn)

        #ski_data = 'C30433FA1975FF193181458FB902B501EA9789DC'
        _ski_data = [ ski_data[i:i+2] for i in range(0, len(ski_data), 2)]
        ski_bin =  [ chr(int(_ski_data[i],16)) for i in range(0,len(_ski_data))]
        bgpsec_data.ski = ski_type('%s' % ''.join(["%s" % x for x in ski_bin]))

        bgpsec_data.algorithmID = 1
        bgpsec_data.status = 1

        hashMsg = SCA_HashMessage()
        hashMsg.ownedByAPI = 0
        hashMsg.bufferSize = self._BUFF_SIZE
        hashMsg.buffer  = None
        hashMsg.segmentCount = 1
        hashMsg.hashMessageValPtr = None
        bgpsec_data.hashMessage = None

        signatureData = SCA_Signature()
        bgpsec_data.signature = ctypes.pointer(signatureData)


        ret_val = self._sign(bgpsec_data)

        ret_sig = None
        if ret_val ==  1:  #API_SUCCESS :1
            ret_sig = [ chr(bgpsec_data.signature.contents.sigBuff[i]) for i in range(0, bgpsec_data.signature.contents.sigLen)]
        return ret_sig






if __name__ == '__main__' :
    print '-------- SRxCryptoAPI library testing WITH CLASS ------------'

    print '++ Initiating'
    crtbgp = CryptoBgpsec()
    crtbgp.crypto_init("PRIV:/users/kyehwanl/proj-bgp/extras/srxcryptoapi/keys/priv-ski-list.txt", 7)

    print '++ Signing'

    ski_data = 'C30433FA1975FF193181458FB902B501EA9789DC'
    ret_sig = crtbgp.crypto_sign(60002, 60003, "10.1.1.2", 24, ski_data)

    print ret_sig
    #exit()

    #path_type = ctypes.c_char_p
    #path_str = path_type("/opt/project/srx_test1/keys/")
    #path_return = setKeyPath(path_str)

    # Before calling sign function, need to call init() function call from the
    # library in order to load private keys used to sign
    #
    # int init(const char* value, int debugLevel, sca_status_t* status);
    #    value:  init_value
    #           = "PUB:/opt/project/srx_test1/keys/ski-list.txt;PRIV:/opt/project/srx_test1/keys/priv-ski-list.txt";

    print '-------- SRxCryptoAPI library testing ------------'
    value_type = ctypes.c_char_p
    value = value_type("PRIV:/users/kyehwanl/proj-bgp/extras/srxcryptoapi/keys/priv-ski-list.txt")
    #value = value_type("PRIV:/opt/project/srx_test1/keys/priv-ski-list.txt")
    initReturnVal = ctypes.c_uint32()
    init(value, 7, initReturnVal)


    host = SCA_BGPSEC_SecurePathSegment()
    #host = ctypes.POINTER(SCA_BGPSEC_SecurePathSegment) ()
    host.pCount = 1
    host.flags = 1
    #host.asn = socket.htonl(65005)
    host.asn = socket.htonl(60002)

    addr = ADDR()
    addr.ipV4 = socket.htonl(struct.unpack("!L", socket.inet_aton("10.1.1.2"))[0])

    nlri = SCA_Prefix()
    nlri.afi = socket.htons(1)
    nlri.safi = 1
    nlri.length = 24
    nlri.addr = addr

    #ski = (ctypes.c_int8 * 20)()
    #signature_ret = SCA_Signature()
    ski_type = ctypes.c_char_p

    bgpsec_data = SCA_BGPSecSignData()
    bgpsec_data.peerAS = socket.htonl(60003)
    #bgpsec_data.myHost = ctypes.POINTER(SCA_BGPSEC_SecurePathSegment)(host)
    bgpsec_data.myHost = ctypes.pointer(host)
    bgpsec_data.nlri = ctypes.pointer(nlri)
    #bgpsec_data.myASN = socket.htonl(65005)
    bgpsec_data.myASN = socket.htonl(60002)

    # 45 CA D0 AC 44 F7 7E FA A9 46 02 E9 98 43 05 21 5B F4 7D CD
    #bgpsec_data.ski = ski_type('123456789ABCDEF'+chr(0x45))
    #ski_data = '45CAD0AC44F77EFAA94602E9984305215BF47DCD'
    ski_data = 'C30433FA1975FF193181458FB902B501EA9789DC'
    _ski_data = [ ski_data[i:i+2] for i in range(0, len(ski_data), 2)]
    ski_bin =  [ chr(int(_ski_data[i],16)) for i in range(0,len(_ski_data))]
    bgpsec_data.ski = ski_type('%s' % ''.join(["%s" % x for x in ski_bin]))
    #bgpsec_data.ski = ski_type(chr(0x45)+chr(0xCA)+chr(0xD0)+chr(0xAC)+chr(0x44)
    #                           +chr(0xF7)+chr(0x7E)+chr(0xFA)+chr(0xA9)+chr(0x46)
    #                           +chr(0x02)+chr(0xE9)+chr(0x98)+chr(0x43)+chr(0x05)
    #                           +chr(0x21)+chr(0x5B)+chr(0xF4)+chr(0x7D)+chr(0xCD))

    bgpsec_data.algorithmID = 1
    bgpsec_data.status = 1

    hashMsg = SCA_HashMessage()
    hashMsg.ownedByAPI = 0
    hashMsg.bufferSize = 100
    hashMsg.buffer  = None
    hashMsg.segmentCount = 1
    hashMsg.hashMessageValPtr = None
    #bgpsec_data.hashMessage = ctypes.pointer(hashMsg)
    bgpsec_data.hashMessage = None

    signatureData = SCA_Signature()
    bgpsec_data.signature = ctypes.pointer(signatureData)

    ret_val = _sign(bgpsec_data)


    #bs = ctypes.POINTER(SCA_BGPSecSignData)()
    #ret_val = _sign(bs)

    # call sign function in library
    #bs = ctypes.POINTER(ctypes.POINTER(SCA_BGPSecSignData))()
    #ret_val = sign(1, bs)
    #ret_val = sign(1, bgpsec_data)

















