import subprocess
import random
import binascii
ss="h"
s=binascii.hexlify(ss.encode())
print(s)
s2=s.decode()
print(s2)

# input_file="plaintext"
# iv=""
# for i in range(0,16):
#     iv+=str(random.randint(0,9))
# ks="ABCDEF1234567812"
#
# subprocess.run(["openssl","enc","-aes-128-cbc","-in",input_file,"-K",ks,"-iv",iv,"-out" ,"encrypted_sender_message"])
