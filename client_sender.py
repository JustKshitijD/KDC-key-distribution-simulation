#print("Sender")
# Import socket module
# md5 - echo -n "Welcome" | md5sum | awk '{print $1}'

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
#input_file="plaintext"


# print(sys.argv)

n=len(sys.argv)
kdc_ip=sys.argv[4]
kdc_port=int(sys.argv[5])   # server's port to which I wanna connect
input_file=sys.argv[3]
my_name=sys.argv[1]
id_b=sys.argv[2]

hostname = socket.gethostname()
my_ip = socket.gethostbyname(hostname)
#my_port=12346  # port where I am listening
my_port=12353  # port where I am listening
s_port=str(my_port)
my_master_key=""
# for i in range(0,16):
#     my_master_key+=str(random.randint(0,9))
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
print("301 message sent to KDC for getting registered: ",reg)
reg2=reg.encode()
s.send(reg2)

str_302=s.recv(1024)
str_302=str_302.decode()
print("302 message got from KDC: ",str_302)

if str_302[:3]=="302":
    print("Registered successfully")

with open("out.txt","r") as fd:
    my_master_key=fd.read()
my_master_key=my_master_key[13:]
print("my_master_key_hash: ",my_master_key)
print("")

time.sleep(15)
s.close()
#################################################################################
# Request for Ks
# Create a socket object
s = socket.socket()

# connect to the server on local computer
s.connect((kdc_ip,kdc_port))
key_req="".encode('latin1')
key_req+=("305").encode('latin1')
id_a=my_name
# id_b="bob"
nonce1="0"
msg=id_a+id_b+nonce1

iv=""
for i in range(0,16):
    iv+=str(random.randint(0,9))

with open("in.txt","w") as fp:
    fp.write(msg)

enc=""
subprocess.run(["openssl","enc","-aes-128-cbc","-in","in.txt","-K",my_master_key,"-iv",iv,"-out" ,"encrypted_sender_message"])
with open("encrypted_sender_message","rb") as fp:
    enc=fp.read()

print("id_a: ",id_a)
print("id_b: ",id_b)
print("iv: ",iv)

key_req+=enc
key_req+=id_a.zfill(12).encode('latin1')    # name padded till 12 bytes
key_req+=iv.encode('latin1')                # I have added iv at end also. NOT GIVEN IN PROBLEM.


print("305 message by sender to KDC : ",key_req.decode('latin1'))
key_req_2=key_req
print("Sending 305 message to KDC....")
s.send(key_req_2)

print("")
print("Receiving 306 message from KDC having Ks....")
enc_msg_2=s.recv(1024)
print("306 message got: ",enc_msg_2.decode('latin1'))
enc_msg_2=enc_msg_2[3:]


with open("in_dec.txt","wb") as fp:
    fp.write(enc_msg_2)

dec=""
subprocess.run(["openssl","enc","-aes-128-cbc","-d","-in","in_dec.txt","-K",my_master_key,"-iv",iv,"-out" ,"decrypted_sender_message"])
with open("decrypted_sender_message","rb") as fp:
    dec=fp.read()

dec=dec.decode('latin1')
ll=8+len(id_a)+len(id_b)+1+16+8

dec2=dec[ll:]
dec2=dec2.encode('latin1')
ks=dec[0:8]

print("Ks extracted from 306 message got from KDC:: ",ks)
# print("dec: ",dec)
# print("dec2: ",dec2)

msg_for_other_client="".encode('latin1')
msg_for_other_client+="309".encode('latin1')
msg_for_other_client+=dec2
idd=id_a.zfill(12).encode('latin1')
msg_for_other_client+=idd
msg_for_other_client+=iv.encode('latin1')  # iv is of 16 bytes


ip_b=""
port_b=""

cc=0
for i in range(0,len(ip_b)):
    if ip_b[i]=='0':
        cc+=1
    else:
        break

ip_b=ip_b[cc:]

cc=0
for i in range(0,len(port_b)):
    if port_b[i]=='0':
        cc+=1
    else:
        break

port_b=port_b[cc:]

ip_b=dec[8+len(id_a)+len(id_b)+1:8+len(id_a)+len(id_b)+1+16]
port_b=dec[8+len(id_a)+len(id_b)+1+16:8+len(id_a)+len(id_b)+1+16+8]

cc=0
for i in range(0,len(ip_b)):
    if ip_b[i]=='0':
        cc+=1
    else:
        break

ip_b=ip_b[cc:]

cc=0
for i in range(0,len(port_b)):
    if port_b[i]=='0':
        cc+=1
    else:
        break

port_b=port_b[cc:]

print("IP address of B extracted from 306 message got from KDC: ",ip_b)
print("Port of B extracted from 306 message got from KDC: ",port_b)

#time.sleep(15)
# time.sleep(10)

s2 = socket.socket()

# connect to the server on local computer
print("309 message for receiver: ",msg_for_other_client.decode('latin1'))
print("Sending this message to receiver.....")
print("")
s2.connect((ip_b,int(port_b)))
s2.send(msg_for_other_client)
s2.close()


# s3 = socket.socket()
#
# # connect to the server on local computer
# s3.bind(('', int(my_port)))
# print ("socket binded to %s" %(my_port))
#
# # put the socket into listening mode
# s3.listen(5)
# c3, addr = s3.accept()
# print ("socket is listening")
# msg_309=c3.recv(1024)
# msg_309=msg_309.decode('latin1')
# print("msg_309: ",msg_309)
# msg_309=msg_309[:-1*len(id_b)]
#
# with open("in_dec.txt","w") as fd:
#     fd.write(msg_309)
#
# dec3=""
# subprocess.run(["openssl","enc","-aes-128-cbc","-d","-in","in_dec.txt","-K",my_master_key,"-iv",iv,"-out" ,"decrypted_sender_message"])
# with open("decrypted_sender_message","rb") as fp:
#     dec3=fp.read()
#
# dec3=dec3.decode('latin1')
# ks3=dec3[:8]
# print("Ks via 309 from receiver:- ".ks3)
#
# c3.close()
# s3.close()
s.close()

ks=ks+8*"0"
s=binascii.hexlify(ks.encode())
ks2=s.decode()

enc=""
subprocess.run(["openssl","enc","-aes-128-cbc","-in",input_file,"-K",ks2,"-iv",iv,"-out" ,"encrypted_sender_message"])
with open("encrypted_sender_message","rb") as fp:
    enc=fp.read()

enc+=iv.encode('latin1')
print("Plaintext input_file encoded with Ks is: ",enc)
s4 = socket.socket()

time.sleep(5)             # wait for receiver to be set in receiver mode to get encoded plaintext
# connect to the server on local computer
s4.connect((ip_b,int(port_b)))
print("Sending this to receiver....")
s4.send(enc)
s4.close()


################################################################################

#
# nn=0
# while True:
#     nn=nn-1
#     nn+=1
