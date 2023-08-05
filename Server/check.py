from binascii import b2a_hex, a2b_hex
from Crypto.Cipher import DES
import sys

#key = '12345678'

while True:
    key = input("Please Input the Key: ")
    if key == "12345678":
        fp = open("ChatRecord", 'r')
        try:
            text = fp.read()
        finally:
            fp.close()

        des_ob = DES.new(key.encode(), DES.MODE_ECB)
        cryp_text = a2b_hex(text)
        dec_text = des_ob.decrypt(cryp_text)
        print("\nChat Records: \n" + dec_text.decode())
        break;
    else:
        result = input("Error! Input the Key AGAIN or Input 'no' to LEAVE: ")
        if result == "no":
            break;
