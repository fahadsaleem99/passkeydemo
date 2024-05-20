#from Balsam.EccEngine import EccEngine
from ICC.EccEngine import EccEngine
import hashlib

from ICC.OctetString import OctetString
#from ICC.TLV import GPCertificate, SimpleTLV
from ICC.crypto import CMAC
from ICC.aes import AES

from collections import OrderedDict

######################################################
# Fahad
######################################################
class Fahad(object):

    def __init__(self):
        self.ecc = EccEngine()
        self.ecc.init_P_256(hashlib.sha256)
        self.setupKeys()

    def setupKeys(self):
        self.ci = self.ecc.generateKeyPair(0x53F4E638F677991D11207BC67264D1C5FD997ACDEB706FD28D70831145587AF0)
        self.casd = self.ecc.generateKeyPair(0x21DA6DD55F595C42CACB46B94DB9CC7DF1B8DC1688855B47450827549FED8D0C)
        self.dp = self.ecc.generateKeyPair(0x2D01324E9F6BBF3D5C7349CDD1DD8894179D9AC2EBD66F59963A389974727309)
        self.ephemeral = self.ecc.generateKeyPair(0x336E343703F3FE2ACC7F1F207823B2BDFBDCEE279B2F5E168D7DABDB293CA754)

        self.tsm = {'Q':[0xfead5c4a828228d917a7e09af85ea935a9162a6d8ce03569642286211c70ba69, 0x1eb2fd16d4eeea07359f7ed922b97b786a1aaf3c49f76014ddeb59ea94bee337] }


    
    def verifSig(self, sig, data):
    	doVerify = self.ecc.ecdsa_verify(sig, data, self.tsm['Q'])
    	return doVerify
    
    def calcSig(self, data):
        #########################
        # Now calculate the signature of a data block which uses a random from the card
        # and is used to ensure the ephemeral key from the DP is not being replayed
        sig = self.ecc.ecdsa_sign(self.dp['d'], data)
        return (OctetString(sig[0], l=32), OctetString(sig[1], l=32))



        
if __name__ == "__main__":
    print ("ECC Tests")
    print


    
    
    #USE THIS for Assertion Verification
    ecc = EccEngine()
    ecc.init_P_256(hashlib.sha256)
    #msg=OctetString("49960de5880e8c687434170f6476605b8fe4aeb9a28632c7995cf3ba831d976305000000002374ac6e68955b09472a527400855879f16e6576892ecbcae2afc4c8bbf86acd")
    msg=OctetString("49960de5880e8c687434170f6476605b8fe4aeb9a28632c7995cf3ba831d97639d00000000a16c6465766963655075624b6579588ca66364706b584da50102032620012158208ff7f70191819dbc991bc2d8fdeeca4db128b865c2b1354d02e19a9ee19d17d02258203c5f84f755724648775c7d8dba2491838624c59246651f9156207c76caf59a8063666d74646e6f6e65656e6f6e6365406573636f7065006661616775696450000000000000000000000000000000006761747453746d74a0812542490338b29fc535da17c046106287f9c118fb6ddabe69a5994c65efe2ab")
    #sig = [0xaad0cf988bb4decd4232a1845043b081ecc98652955af9360dfb61a00a50d409, 0xa4be133469c7b2ac26dda9e890eea8fec2e08b7b4e8e70704a4a46d3a60301a5]
    sig = [0xc14a7ce61d8b033bf7f7d428e7999c5cadfc75ef64d95272609c9041720759af, 0x7f706b578df6136b866618900d6c8b77730702f89502c6e1b90d33c97c5fa3f9]
    Q = [0xa0b69600ba6c9b1352bc211f2bedc1701886191570fccc2cb5660a7ef425af82, 0x96c398c2df11ceb96ab771fa6ac4b701c6f0acd01e6888c097b308ec7010fc9d]
    print ("Assertion Verified using given PK: %s" % ecc.ecdsa_verify(sig, msg, Q))
    
    #DPK Assertion
    dpkdata=OctetString("49960de5880e8c687434170f6476605b8fe4aeb9a28632c7995cf3ba831d97639d00000000a16c6465766963655075624b6579588ca66364706b584da50102032620012158208ff7f70191819dbc991bc2d8fdeeca4db128b865c2b1354d02e19a9ee19d17d02258203c5f84f755724648775c7d8dba2491838624c59246651f9156207c76caf59a8063666d74646e6f6e65656e6f6e6365406573636f7065006661616775696450000000000000000000000000000000006761747453746d74a0d7d7cb5e4939ffe874c5a4e13e974c076162a8c99f0ccaac4bf623553caef37f")
    dpksig = [0xe028c71cc2f37c8b4fac64c0e186f42061a9bc7057edd88f978a5934d63d6cca, 0x4348895eba9b0f334ad8556c862c4fe2222d8a4e04720ee4bcdb6594c0bbd5ca]
    dpkQ = [0x8ff7f70191819dbc991bc2d8fdeeca4db128b865c2b1354d02e19a9ee19d17d0, 0x3c5f84f755724648775c7d8dba2491838624c59246651f9156207c76caf59a80]
    print ("DPK Assertion Verified using given PK: %s" % ecc.ecdsa_verify(dpksig, dpkdata, dpkQ))
    
    
    #data for ATTESTATION verif for DPK: "static value||aaguid||dpk||nonce"
    #static value= 64657669636520626f756e64206b6579206174746573746174696f6e2073696700ffffffff
    dpkdata=OctetString("64657669636520626f756e64206b6579206174746573746174696f6e2073696700ffffffff00000000000000000000000000000000a50102032620012158208ff7f70191819dbc991bc2d8fdeeca4db128b865c2b1354d02e19a9ee19d17d02258203c5f84f755724648775c7d8dba2491838624c59246651f9156207c76caf59a80")
    dpksig = [0xa5a31d231ebf89e1e0576372935831843dfb688182b07d3fb7701cb9a34920e7, 0x1bf6b93c14a5b76b91268ee565a40e139cf6be16aa3d6cab8d50214ad74f9d80]
    dpkQ = [0x8ff7f70191819dbc991bc2d8fdeeca4db128b865c2b1354d02e19a9ee19d17d0, 0x3c5f84f755724648775c7d8dba2491838624c59246651f9156207c76caf59a80]
    print ("DPK Assertion Verified using given PK: %s" % ecc.ecdsa_verify(dpksig, dpkdata, dpkQ))
    

