
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

#typedef struct
#{
#  u_int32_t    myAS;
#  sca_status_t status;
#  u_int8_t*    bgpsec_path_attr;
#  SCA_Prefix*  nlri;
#  SCA_HashMessage*  hashMessage[2];
#} SCA_BGPSecValidationData;

# structure SCA_BGPSecValidationData {}
class SCA_BGPSecValidationData(ctypes.Structure):
    _fields_ = [('myAS',        ctypes.c_uint32),
                ('status',      ctypes.c_uint32),
                ('bgpsec_path_attr', ctypes.c_char_p),
                ('nlri',        ctypes.POINTER(SCA_Prefix)),
                ('hashMessage', ctypes.POINTER(SCA_HashMessage) * 2)]


class CryptoBgpsec() :

    _BUFF_SIZE = 100
    _ALGO_ID = 1
    _PCOUNT = 1
    _FLAGS = 0
    _SCA_ECDSA_ALGORITHM = 1
    _crypto_init_config = False

    # ctype variable declaration
    bgpsec_openssl_lib = None
    bgpsec_libloc   = None
    bgpsec_openssl  = None
    srxcryptoapi    = None
    sign            = None
    #_sign           = None
    init            = None
    setKeyPath      = None
    sca_generateHashMessage = None

    bgpsec_ValidationData = []

    def __init__ (self, negotiated=None):
        self.negotiated = negotiated

        if not CryptoBgpsec._crypto_init_config : # only once execution
            CryptoBgpsec._crypto_init_config = True
            self.crypto_init_value_type = ctypes.c_char_p

            if negotiated != None :
                CryptoBgpsec.bgpsec_openssl_lib = self.negotiated.neighbor.bgpsec_openssl_lib[0]
                CryptoBgpsec.bgpsec_libloc = self.negotiated.neighbor.bgpsec_libloc[0]
            else :
                CryptoBgpsec.bgpsec_openssl_lib = '/users/kyehwanl/Quagga_test/Proces_Performance/QuaggaSRxSuite/_inst/lib/srx/libSRxBGPSecOpenSSL.so'
                CryptoBgpsec.bgpsec_libloc = '/users/kyehwanl/Quagga_test/Proces_Performance/QuaggaSRxSuite/_inst/lib/srx/libSRxCryptoAPI.so'

            self._path = os.path.join(*(os.path.split(__file__)[:-1] + (CryptoBgpsec.bgpsec_openssl_lib,)))
            #CryptoBgpsec.bgpsec_openssl = ctypes.cdll.LoadLibrary(self._path, mode=ctypes.RTLD_GLOBAL)
            CryptoBgpsec.bgpsec_openssl = ctypes.cdll.LoadLibrary(self._path)

            self._path_crypto = os.path.join(*(os.path.split(__file__)[:-1] + (self.bgpsec_libloc,)))
            CryptoBgpsec.srxcryptoapi = ctypes.cdll.LoadLibrary(self._path_crypto )


            # int sign(int count, SCA_BGPSecSignData** bgpsec_data)
            CryptoBgpsec.sign = CryptoBgpsec.bgpsec_openssl.sign
            CryptoBgpsec.sign.argtypes = (ctypes.c_int, ctypes.POINTER(ctypes.POINTER(SCA_BGPSecSignData)))
            CryptoBgpsec.sign.restype = ctypes.c_int

            ## int _sign(SCA_BGPSecSignData* bgpsec_data)
            #CryptoBgpsec._sign = CryptoBgpsec.bgpsec_openssl._sign
            #CryptoBgpsec._sign.argtypes = ctypes.POINTER(SCA_BGPSecSignData),
            #CryptoBgpsec._sign.restype = ctypes.c_int

            # int init(const char* value, int debugLevel, sca_status_t* status);
            CryptoBgpsec.init = CryptoBgpsec.bgpsec_openssl.init
            CryptoBgpsec.init.argtypes = (ctypes.POINTER(ctypes.c_char), ctypes.c_int, ctypes.POINTER(ctypes.c_uint32))
            CryptoBgpsec.init.restype = ctypes.c_int

            #int sca_generateHashMessage(SCA_BGPSecValidationData* data, u_int8_t algoID, sca_status_t* status)
            CryptoBgpsec.sca_generateHashMessage = CryptoBgpsec.srxcryptoapi.sca_generateHashMessage
            CryptoBgpsec.sca_generateHashMessage.argtype = (ctypes.POINTER(SCA_BGPSecValidationData),
                                            ctypes.c_uint8, ctypes.POINTER(ctypes.c_uint32))
            CryptoBgpsec.sca_generateHashMessage.restype = ctypes.c_int


            CryptoBgpsec.setKeyPath = CryptoBgpsec.srxcryptoapi.sca_SetKeyPath
            CryptoBgpsec.setKeyPath.argtypes = ctypes.POINTER(ctypes.c_char),
            CryptoBgpsec.setKeyPath.restype = ctypes.c_int
            self.bgpsec_key_volt = self.negotiated.neighbor.bgpsec_key_volt[0]

        self.hashMessageData = None



    def crypto_init (self, init_str, debug_type):

        path_type = ctypes.c_char_p
        path_str = path_type(self.bgpsec_key_volt)
        CryptoBgpsec.setKeyPath(path_str)

        ret_init_value = self.crypto_init_value_type(init_str)
        initReturnVal = ctypes.c_uint32()

        # call API's init function
        CryptoBgpsec.init(ret_init_value, debug_type, initReturnVal)
        #return initReturnVal


    def crypto_sign (self, host_asn, peer_asn, nlri_ip, nlri_mask, ski_data, bgpsec_pre_attrs=None ) :

        host = SCA_BGPSEC_SecurePathSegment()
        host.pCount = 1
        host.flags = 0
        host.asn = socket.htonl(host_asn)

        addr = ADDR()
        addr.ipV4 = socket.htonl(struct.unpack("!L", socket.inet_aton(nlri_ip))[0])

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

        if bgpsec_pre_attrs:
            bgpsec_data.hashMessage = self.hashMessageData
        else:
            bgpsec_data.hashMessage = None

        signatureData = SCA_Signature()
        bgpsec_data.signature = ctypes.pointer(signatureData)


        #ret_val = CryptoBgpsec._sign(bgpsec_data)
        ret_val = CryptoBgpsec.sign(1, ctypes.pointer(bgpsec_data))

        ret_sig = None
        if ret_val ==  1:  #API_SUCCESS :1
            ret_sig = [chr(bgpsec_data.signature.contents.sigBuff[i])
                       for i in range(0, bgpsec_data.signature.contents.sigLen)]
        return ret_sig



    def make_bgpsecValData (self, host_asn, nlri_ip, nlri_mask, bgpsec_attrs) :

        if not bgpsec_attrs :
            return 0

        addr = ADDR()
        addr.ipV4 = socket.htonl(struct.unpack("!L", socket.inet_aton(nlri_ip))[0])

        nlri = SCA_Prefix()
        nlri.afi = socket.htons(1)
        nlri.safi = 1
        nlri.length = nlri_mask
        nlri.addr = addr

        valData = SCA_BGPSecValidationData()
        valData.myAS = socket.htonl(host_asn)
        valData.status = 1
        valData.bgpsec_path_attr = bgpsec_attrs
        valData.nlri = ctypes.pointer(nlri)
        #valData.hashMessage = None

        statusReturnVal = ctypes.c_uint32()
        retByte = CryptoBgpsec.sca_generateHashMessage(ctypes.pointer(valData),
                                               self._SCA_ECDSA_ALGORITHM, statusReturnVal)
        if statusReturnVal.value != 0: # API_STATUS_OK: 0
            return 0

        self.hashMessageData = valData.hashMessage[0]

        print '%d byte used from calling genenrate-HashMessage' % retByte
        hLen = valData.hashMessage[0].contents.hashMessageValPtr[0].contents.hashMessageLength
        for i in range (hLen):
            print hex(valData.hashMessage[0].contents.hashMessageValPtr[0].contents.hashMessagePtr[i]),
        print '\r'


        return retByte



if __name__ == '__main__' :

    """ -------------------------------------------------------------------
     < import C Library>
    ------------------------------------------------------------------- """
    bgpopenssl_file     = '/users/kyehwanl/Quagga_test/Proces_Performance/QuaggaSRxSuite/_inst/lib/srx/libSRxBGPSecOpenSSL.so'
    srxcryptoapi_file   = '/users/kyehwanl/Quagga_test/Proces_Performance/QuaggaSRxSuite/_inst/lib/srx/libSRxCryptoAPI.so'
    #bgpopenssl_file     = '/tmp/api/_inst/lib/srx/libSRxBGPSecOpenSSL.so'
    #srxcryptoapi_file   = '/tmp/api/_inst/lib/srx/libSRxCryptoAPI.so'
    _path = os.path.join(*(os.path.split(__file__)[:-1] + (bgpopenssl_file,)))
    _path_crypto = os.path.join(*(os.path.split(__file__)[:-1] + (srxcryptoapi_file,)))

    srxcryptoapi = ctypes.cdll.LoadLibrary(_path_crypto )
    bgpopenssl = ctypes.cdll.LoadLibrary(_path)
    #bgpopenssl = ctypes.CDLL(_path, mode=ctypes.RTLD_GLOBAL)


    SCA_ECDSA_ALGORITHM = 1

    """ -------------------------------------------------------------------
     < Library method Declarations >
    ------------------------------------------------------------------- """
    # int sign(int count, SCA_BGPSecSignData** bgpsec_data)
    sign = bgpopenssl.sign
    sign.argtypes = (ctypes.c_int, ctypes.POINTER(ctypes.POINTER(SCA_BGPSecSignData)))
    sign.restype = ctypes.c_int


    ## int _sign(SCA_BGPSecSignData* bgpsec_data)
    #_sign = bgpopenssl._sign
    #_sign.argtypes = ctypes.POINTER(SCA_BGPSecSignData),
    #_sign.restype = ctypes.c_int

    # int init(const char* value, int debugLevel, sca_status_t* status);
    init = bgpopenssl.init
    init.argtypes = (ctypes.POINTER(ctypes.c_char), ctypes.c_int, ctypes.POINTER(ctypes.c_uint32))
    init.restype = ctypes.c_int

    """
    # sca_SetKeyPath needed in libSRxCryptoAPI.so
    # int sca_SetKeyPath (char* key_path)
    #       sca_SetKeyPath((char *)key_volt);
    # key_volt = "/opt/project/srx_test1/keys/";
    """

    setKeyPath = srxcryptoapi.sca_SetKeyPath
    setKeyPath.argtypes = ctypes.POINTER(ctypes.c_char),
    setKeyPath.restype = ctypes.c_int

    #void sca_printStatus(sca_status_t status)

    #sca_printStatus = srxcryptoapi.sca_printStatus
    #sca_printStatus.argtype = ctypes.c_uint32
    #sca_printStatus.restype = None

    """
    int sca_generateHashMessage(SCA_BGPSecValidationData* data, u_int8_t algoID,
                                sca_status_t* status)
    """
    sca_generateHashMessage = srxcryptoapi.sca_generateHashMessage
    sca_generateHashMessage.argtype = (ctypes.POINTER(SCA_BGPSecValidationData),
                                    ctypes.c_uint8, ctypes.POINTER(ctypes.c_uint32))
    sca_generateHashMessage.restype = ctypes.c_int





    """
    -------------------------------------------------------------------
     <Test with a CLASS instance>
    print '--- BGPSec OpenSSL library testing WITH CLASS '
    print '++ Initiating'
    crtbgp = CryptoBgpsec()
    crtbgp.crypto_init("PRIV:/users/kyehwanl/proj-bgp/extras/srxcryptoapi/keys/priv-ski-list.txt", 7)

    print '++ Signing'

    ski_data = 'C30433FA1975FF193181458FB902B501EA9789DC'
    ret_sig = crtbgp.crypto_sign(60002, 60003, "10.1.1.2", 24, ski_data)

    print ret_sig
    #exit()
    -------------------------------------------------------------------
    """

    #val = ctypes.c_char_p.in_dll(srxcryptoapi, "_keyPath")
    #print(val)

    """ -------------------------------------------------------------------
     < Testing SRxCryptoAPI library >
    ------------------------------------------------------------------- """
    print '-------- Testing SRxCryptoAPI library ----------'
    path_type = ctypes.c_char_p
    #path_str = path_type("/opt/project/srx_test1/keys/")
    path_str = path_type("/users/kyehwanl/proj-bgp/extras/srxcryptoapi/keys")
    path_return = setKeyPath(path_str)
    print "path(%s) return val: %d" % (path_str.value, path_return)
    #print(val)

    #sca_printStatus(1) # works



    """
    -------------------------------------------------------------------
     Before calling sign function, need to call init() function call from the
     library in order to load private keys used to sign

     int init(const char* value, int debugLevel, sca_status_t* status);
        value:  init_value
               = "PUB:/opt/project/srx_test1/keys/ski-list.txt;PRIV:/opt/project/srx_test1/keys/priv-ski-list.txt";
    -------------------------------------------------------------------
    """

    print '--- BGPSec OpenSSL library testing '
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

    """ call _sign function in library """
    """ int _sign(SCA_BGPSecSignData* bgpsec_data)  """
    #ret_val = _sign(bgpsec_data)



    print "ctypes sign function called"
    """ call sign function in library """
    """ int sign(int count, SCA_BGPSecSignData** bgpsec_data)  """
    ret_val = sign(1, ctypes.pointer(bgpsec_data))


    """
    Testing sca-generationHashMessage in SRxCryptoAPI library
    """
    bgpsec_attr_type = ctypes.c_char_p
    bgpsec_attrs = [
        0x90, 0x21, 0x00, 0x68, 0x00, 0x08, 0x01, 0x00, 0x00, 0x00, 0xfd, 0xf3,
        0x00, 0x60, 0x01, 0x45, 0xca, 0xd0, 0xac, 0x44, 0xf7, 0x7e, 0xfa, 0xa9, 0x46, 0x02, 0xe9, 0x98,
        0x43, 0x05, 0x21, 0x5b, 0xf4, 0x7d, 0xcd, 0x00, 0x47, 0x30, 0x45, 0x02, 0x21, 0x00, 0xb3, 0xe8,
        0xcc, 0xd2, 0xcb, 0xba, 0x96, 0x47, 0xe3, 0x1f, 0x74, 0x97, 0xa3, 0x77, 0x74, 0x55, 0x86, 0x44,
        0x09, 0x67, 0xec, 0x02, 0x60, 0x3f, 0x05, 0xe2, 0x1b, 0x47, 0x62, 0xab, 0xde, 0xd9, 0x02, 0x20,
        0x05, 0x58, 0xe5, 0x72, 0xc5, 0x61, 0x91, 0x47, 0x99, 0x86, 0x16, 0x3e, 0x1e, 0x4a, 0x92, 0x5e,
        0xe8, 0x26, 0x03, 0x1f, 0x5d, 0x5a, 0x36, 0x92, 0x18, 0x1e, 0x8b, 0x3e, 0xa7, 0x26, 0x4b, 0x61]

    battrs_bin = [ chr(bgpsec_attrs[i]) for i in range (0, len(bgpsec_attrs))]
    battrs_str = bgpsec_attr_type('%s' % ''.join(["%s" % x for x in battrs_bin]))

    hashMsgData = SCA_HashMessage()

    valData = SCA_BGPSecValidationData()
    valData.myAS = socket.htonl(60003)
    valData.status = 1
    valData.bgpsec_path_attr = battrs_str
    #valData.bgpsec_path_attr = ctypes.pointer(signatureData)
    valData.nlri = ctypes.pointer(nlri)
    #valData.hashMessage = ctypes.pointer(hashMsgData)


    statusReturnVal = ctypes.c_uint32()
    retByte = sca_generateHashMessage(ctypes.pointer(valData), SCA_ECDSA_ALGORITHM, statusReturnVal)

    print "status return value: %d " % statusReturnVal.value # API_STATUS_OK : 0
    print '%d byte used from calling genenrate-HashMessage' % retByte
    hLen = valData.hashMessage[0].contents.hashMessageValPtr[0].contents.hashMessageLength
    #result = [chr(i) for i in valData.hashMessage[0].contents.hashMessageValPtr[0].contents.hashMessagePtr]

    for i in range (hLen):
        print hex(valData.hashMessage[0].contents.hashMessageValPtr[0].contents.hashMessagePtr[i]),













