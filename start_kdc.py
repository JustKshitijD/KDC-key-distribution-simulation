import sys
import subprocess
import os
import base64
import random
import time

kdc_dict={}
client_session_keys={}

n=len(sys.argv)
subprocess.run(["rm","kdc_out.txt"])
subprocess.run(["rm","kdc_pwd"])

port = int(sys.argv[1])
outfilename=sys.argv[2]
pwdfile=sys.argv[3]

# port=12345
# outfilename="kdc_out.txt"
# pwdfile="kdc_pwd"


# first of all import the socket library
import socket

# next create a socket object
s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
#print ("Socket successfully created")



# Next bind to the port
# we have not typed any ip in the ip field
# instead we have inputted an empty string
# this makes the server listen to requests
# coming from other computers on the network
s.bind(('', port))
print ("socket binded to %s" %(port))

# put the socket into listening mode
s.listen(5)
print ("socket is listening for clients")

# a forever loop until we interrupt it or
# an error occurs
start=time.time()

cnt=0

while cnt<2:
    cnt+=1
    # Establish connection with client.
    c, addr = s.accept()
    print ('Got connection from', addr )

    ##############################################################################
    x=c.recv(1024)
    y=x.decode()
    print("301 message got from client : ",y)
    # Register client
    #client_key=y[-28:-12]
    client_key=y[-24:-12]
    print("12 byte client key extracted from message: ",client_key)
    with open('in.txt','w') as fd:
        fd.write(client_key)

    f=open("out.txt","w")
    subprocess.run(["openssl" ,"dgst" ,"-md5","in.txt"],stdout=f)
    with open("out.txt","r") as fd:
        client_key=fd.read()

    client_key=client_key[13:]
    print("18 byte MD5 hash generated for the client_key: ",client_key)
    key_bytes = client_key.encode('ascii')
    base64_bytes = base64.b64encode(key_bytes)
    base64_message = base64_bytes.decode('ascii')
    print("The md5 hash is stored in base64 format thus- ",base64_message)
    #print("base64 message: ",base64_message)

    client_name=y[-12:]
    client_port=y[-32:-24]
    client_ip=y[3:19]

    cc=0
    for i in range(0,len(client_name)):
        if client_name[i]=='0':
            cc+=1
        else:
            break

    client_name=client_name[cc:]

    cc=0
    for i in range(0,len(client_port)):
        if client_port[i]=='0':
            cc+=1
        else:
            break

    client_port=client_port[cc:]

    cc=0
    for i in range(0,len(client_ip)):
        if client_ip[i]=='0':
            cc+=1
        else:
            break

    client_ip=client_ip[cc:]

    print("client_name as extracted from 301 message: ",client_name)
    print("client_port as extracted from 301 message: ",client_port)
    print("client_ip as extracted from 301 message: ",client_ip)

    stored=""
    stored+=":"
    stored+=client_name
    stored+=":"
    stored+=client_ip
    stored+=":"
    stored+=client_port
    stored+=":"
    stored+=base64_message
    stored+=":"

    print("Text to stored in password file of KDC: ",stored)

    str_302="302"
    str_302+=client_name
    print("Text to be stored in Output file of KDC: ",y)

    print("")
    print("302 message to be sent to client: ",str_302)
    print("Sending this message....")
    c.send(str_302.encode())

    with open(outfilename,'a') as fp:
        fp.write(y+"\n")

    kdc_dict[client_name]=stored

    with open(pwdfile,"a") as fp:
        fp.write(stored+"\n")

print("---------------------------------------------------------------------")

ccc=0
while ccc<1:
    #####################################################################4
    c, addr = s.accept()
    # Give Ks to client
    ccc+=1
    #print("Ks- ",ccc)
    y=c.recv(1024)
    y=y.decode('latin1')
    print("305 message got from sender: ",y)

    iv=y[-16:]
    client_name=y[-28:-16]
    #print("y2: ",y)
    print("Client name: ",client_name)
    enc=y[3:-28].encode('latin1')

    cc=0
    for i in range(0,len(client_name)):
        if client_name[i]=='0':
            cc+=1
        else:
            break

    client_name=client_name[cc:]

    pwd=kdc_dict[client_name]
    print("Password corresponding to this client got from password file: ",pwd)

    cnt=0
    client_master_key=""

    for i in range(len(pwd)-1,-1,-1):
        if pwd[i]==":":
            cnt+=1
            if cnt==2:
                break
        else:
            client_master_key=pwd[i]+client_master_key

    key_bytes = client_master_key.encode('ascii')
    bytes = base64.b64decode(key_bytes)
    client_master_key = bytes.decode('ascii')
    print("Client_master_key for this client: ",client_master_key)

    #print("enc: ",enc)
    print("Decoding 305 message....")
    with open("in_dec.txt","wb") as fp:
        fp.write(enc)

    dec=""
    subprocess.run(["openssl","enc","-aes-128-cbc","-d","-in","in_dec.txt","-K",client_master_key,"-iv",iv,"-out" ,"decrypted_sender_message"])
    with open("decrypted_sender_message","r") as fp:
        dec=fp.read()

    #print("dec: ",dec)


    client2=dec[len(client_name):-1]
    nonce1=dec[-1]
    print("client2: ",client2)
    pwd2=kdc_dict[client2]

    kk=0
    ip_a=""
    port_a=""
    for i in range(len(client_name)+2,len(pwd)):
        if pwd[i]==":":
            break
        ip_a+=pwd[i]
        kk+=1

    for i in range(len(client_name)+2+kk+1,len(pwd)):
        if pwd[i]==":":
            break
        port_a+=pwd[i]

    kk=0
    ip_b=""
    port_b=""
    for i in range(len(client2)+2,len(pwd2)):
        if pwd2[i]==":":
            break
        ip_b+=pwd2[i]
        kk+=1

    for i in range(len(client2)+2+kk+1,len(pwd2)):
        if pwd2[i]==":":
            break
        port_b+=pwd2[i]


    print("IP for sender: ",ip_a)
    print("IP for receiver: ",ip_b)
    print("Port of sender: ",port_a)
    print("Port of receiver: ",port_b)

    cnt=0
    client_2_key=""

    for i in range(len(pwd2)-1,-1,-1):
        if pwd2[i]==":":
            cnt+=1
            if cnt==2:
                break
        else:
            client_2_key=pwd2[i]+client_2_key

    key_bytes = client_2_key.encode('ascii')
    bytes = base64.b64decode(key_bytes)
    client_2_key = bytes.decode('ascii')
    print("Master key of receiver: ",client_2_key)

    l=[]
    for i in range(97, 123):      # key value can only be 0-9 right?
	    l.append(chr(i))
    for i in range(65, 71):          # A to F
	    l.append(chr(i))
    for i in range(48,57):
        l.append(chr(i))

    msg1=""
    ks=""
    l2=[]
    l2.append(client_name)
    l2.append(client2)
    l2.sort()
    flag=False

    pair=(l2[0],l2[1])
    if pair in client_session_keys:
        ks=client_session_keys[pair]
        print("Ks for the pairs already present with KDC as:- ",ks)
        flag=True

    if flag is False:
        for i in range(0,8):
            kk=random.randint(0,len(l)-1)
            ks+=l[kk]
    print("Ks for this (client,server) pair is: ",ks)

    msg1+=(ks+client_name+client2+nonce1+ip_a.zfill(16)+port_a.zfill(8))   #IP and port filled again
    if flag is False:
        l2=[]
        l2.append(client_name)
        l2.append(client2)
        l2.sort()
        client_session_keys[(l2[0],l2[1])]=ks

    with open("in.txt","w") as fp:
        fp.write(msg1)

    enc=""
    subprocess.run(["openssl","enc","-aes-128-cbc","-in","in.txt","-K",client_2_key,"-iv",iv,"-out" ,"encrypted_sender_message"])
    with open("encrypted_sender_message","rb") as fp:
        enc=fp.read()

    #print("enc_msg_1: ",enc)
    #print("ks out2: ",ks)

    msg2=ks+client_name+client2+nonce1+ip_a.zfill(16)+port_b.zfill(8)
    #print("msg2: ",msg2)
    msg2=msg2.encode('latin1')
    msg2+=enc

    with open("in.txt","wb") as fp:
        fp.write(msg2)

    enc=""
    subprocess.run(["openssl","enc","-aes-128-cbc","-in","in.txt","-K",client_master_key,"-iv",iv,"-out" ,"encrypted_sender_message"])
    with open("encrypted_sender_message","rb") as fp:
        enc=fp.read()

    #print("enc_msg_2: ",enc)

    enc="306".encode('latin1')+enc
    #print("final_enc: ",enc)
    print("306 message is- ",enc.decode('latin1'))
    print("Sending 306 message to sender....")
    c.send(enc)


    #####################################################################
