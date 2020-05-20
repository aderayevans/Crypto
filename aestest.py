import pyDes as pds
import base64

def des_ecb_encode(source, key):
    des_obj = pds.des(key, pds.ECB, IV=None, pad=None, padmode=pds.PAD_PKCS5)
    des_result = des_obj.encrypt(source)
    return base64.encodebytes(des_result)


if __name__ == '__main__':

    src = bytearray.fromhex('8787878787878787')
    key = bytearray.fromhex('0E329232EA6D0D73')
    encrypted = des_ecb_encode(src, key)
    print('encrypted: ', encrypted.hex())
