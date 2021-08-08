#print("Sender")
# Import socket module
import socket
import sys
import subprocess
import os
from random import choice
from string import ascii_lowercase
import time
import random
import binascii

# kdc_ip="127.0.0.1"
# kdc_port=12345
# outenc="outenc.txt"
# outfile="outfile.txt"

# print(sys.argv)

n=len(sys.argv)
kdc_ip=sys.argv[4]
kdc_port=int(sys.argv[5])   # server's port to which I wanna connect
outenc=sys.argv[2]
outfile=sys.argv[3]
my_name=sys.argv[1]

hostname = socket.gethostname()
my_ip = socket.gethostbyname(hostname)
# my_port=12347  # port where I am listening
my_port=12350  # port where I am listening
s_port=str(my_port)
# my_name="bob"
my_master_key=""
for i in range(0,12):
    my_master_key+=str(random.randint(0,9))

with open('in.txt','w') as fd:
    fd.write(my_master_key)

f=open("out.txt","w")
subprocess.run(["openssl" ,"dgst" ,"-md5","in.txt"],stdout=f)


####################################################################################
# # Register to KDC
# Create a socket object
s = socket.socket()

# connect to the server on local computer
s.connect((kdc_ip,kdc_port))
reg=""
reg+="301"
reg+=my_ip.zfill(16)
reg+=s_port.zfill(8)
reg+=my_master_key
reg+=my_name.zfill(12)
print("301 Message sent to KDC for getting registered: ",reg)
reg2=reg.encode()
print("Sending 301 message...")
s.send(reg2)

print("")
print("Receiving 302 message from KDC.....")
str_302=s.recv(1024)
str_302=str_302.decode()
print("302 message got from KDC: ",str_302)

if str_302[:3]=="302":
    print("Registered successfully")

with open("out.txt","r") as fd:
    my_master_key=fd.read()
my_master_key=my_master_key[13:]
print("my_master_key_hash: ",my_master_key)

# s2 = socket.socket()
#
# # connect to the server on local computer
# s2.connect((kdc_ip,kdc_port))
# msg_309=s2.recv(1024)
# msg_309=msg_309.decode()
# print("msg_309: ",msg_309)

#time.sleep(20)
#################################################################################
# # Request for Ks
# # Create a socket object
# s = socket.socket()
#
# # connect to the server on local computer
# s.connect((kdc_ip,kdc_port))
# key_req="".encode('latin1')
# key_req+=("305").encode('latin1')
# id_a=my_name
# id_b="alice"
# nonce1="0"
# msg=id_a+id_b+nonce1
# print("sender_message: ",msg)
#
# iv=""
# for i in range(0,16):
#     iv+=str(random.randint(0,9))
#
# with open("in.txt","w") as fp:
#     fp.write(msg)
#
# enc=""
# subprocess.run(["openssl","enc","-aes-128-cbc","-in","in.txt","-K",my_master_key,"-iv",iv,"-out" ,"encrypted_sender_message"])
# with open("encrypted_sender_message","rb") as fp:
#     enc=fp.read()
#
# print("enc: ",enc)
# key_req+=enc
# key_req+=id_a.zfill(12).encode('latin1')    # name padded till 12 bytes
# key_req+=iv.encode('latin1')                # I have added iv at end also. NOT GIVEN IN PROBLEM.
#
# print("key_req: ",key_req)
# key_req_2=key_req
# s.send(key_req_2)
#
#
# enc_msg_2=s.recv(1024)
# print("enc_msg_2: ",enc_msg_2)
# enc_msg_2=enc_msg_2[3:]
#
#
# with open("in_dec.txt","wb") as fp:
#     fp.write(enc_msg_2)
#
# dec=""
# subprocess.run(["openssl","enc","-aes-128-cbc","-d","-in","in_dec.txt","-K",my_master_key,"-iv",iv,"-out" ,"decrypted_sender_message"])
# with open("decrypted_sender_message","rb") as fp:
#     dec=fp.read()
#
# dec=dec.decode('latin1')
# ll=8+len(id_a)+len(id_b)+1+16+8
#
# dec2=dec[ll:]
# dec2=dec2.encode('latin1')
# ks=dec[0:8]
#
# print("ks: ",ks)
# print("dec: ",dec)
# print("dec2: ",dec2)
#
# msg_for_other_client="".encode('latin1')
# msg_for_other_client+="309".encode('latin1')
# msg_for_other_client+=dec2
# msg_for_other_client+=my_name.encode('latin1')
#
# print("msg_for_other_client: ",msg_for_other_client)
#
# ip_b=""
# port_b=""
# ip_b=dec[8+len(id_a)+len(id_b)+1:8+len(id_a)+len(id_b)+1+16]
# port_b=dec[8+len(id_a)+len(id_b)+1+16:8+len(id_a)+len(id_b)+1+16+8]
#
# cc=0
# for i in range(0,len(ip_b)):
#     if ip_b[i]=='0':
#         cc+=1
#     else:
#         break
#
# ip_b=ip_b[cc:]
#
# cc=0
# for i in range(0,len(port_b)):
#     if port_b[i]=='0':
#         cc+=1
#     else:
#         break
#
# port_b=port_b[cc:]
#
# print("ip_b: ",ip_b)
# print("port_b: ",port_b)

s2 = socket.socket()
s2.bind(('', int(my_port)))
print("")
print ("socket binded to %s" %(my_port))

# put the socket into listening mode
s2.listen(5)
print ("socket is listening for sender to connect and send 309 message, which has Ks")
c2, addr = s2.accept()
msg_309=c2.recv(1024)                   # set to receive from sender
c2.close()
s2.close()

msg_309=msg_309.decode('latin1')
print("309 message: ",msg_309)
iv=msg_309[-16:]
id_b=msg_309[-28:-16]
msg_309=msg_309[3:-28]
msg_309=msg_309.encode('latin1')
with open("in_dec.txt","wb") as fd:
    fd.write(msg_309)

dec3=""
subprocess.run(["openssl","enc","-aes-128-cbc","-d","-in","in_dec.txt","-K",my_master_key,"-iv",iv,"-out" ,"decrypted_sender_message"])
with open("decrypted_sender_message","rb") as fp:
    dec3=fp.read()

#print("dec3: ",dec3)
dec3=dec3.decode('latin1')
ks=dec3[:8]
print("Ks extracted from 309 from sender:- ",ks)



#time.sleep(5)                    # give time to sender to go into receiving mode

# s3 = socket.socket()
#
# # connect to the server on local computer
# s3.connect((ip_b,int(port_b)))
# s3.send(msg_for_other_client)
# s3.close()
#
# s.close()

s4 = socket.socket()

# connect to the server on local computer
s4.bind(('', int(my_port)))
print("")
print ("socket binded to %s" %(my_port))

# put the socket into listening mode
s4.listen(5)
c4, addr = s4.accept()
print ("socket is listening for sender to connect and send text encrypted with Ks..... ")
msg_fin=c4.recv(1024)
msgg=msg_fin.decode('latin1')
msgg2=msgg[:-16]
iv=msgg[-16:]
msgg2=msgg2.encode('latin1')
print("Encoded message got from sender: ",msgg2)
c4.close()

with open(outenc,"wb") as fp:
    fp.write(msgg2)

ks=ks+8*"0"
s=binascii.hexlify(ks.encode())
ks2=s.decode()

dec=""
subprocess.run(["openssl","enc","-aes-128-cbc","-d","-in",outenc,"-K",ks2,"-iv",iv,"-out" ,outfile])

finn=""
with open(outfile,"r") as fp:
    finn=fp.read()
print("Decoding this message....")
print("Decoded message of sender : ",finn)

################################################################################


# nn=0
# while True:
#     nn=nn-1
#     nn+=1
