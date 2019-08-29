#! /usr/bin/python
# coding:utf-8
'''  https://github.com/p7e4/ph3c
$ sudo python ph3c.py
--> Sent EAPOL Start
Got EAP_TYPE_NOTE
--> Send EAP response with Notification
Got EAP Request for identity
--> Sent EAP response with identity
Got EAP Request for MD5 challenge
--> Send EAP response with MD5 challenge
Got EAP Success
'''

import os, sys
### Just check

from socket import socket, htons, AF_PACKET, SOCK_RAW
from ConfigParser import ConfigParser
from struct import pack, unpack
from subprocess import call
from md5 import md5

### Constants

ETHERTYPE_PAE = 0x888e
PAE_GROUP_ADDR = "\x01\x80\xc2\x00\x00\x03"

EAPOL_VERSION = 1
EAPOL_EAPPACKET = 0
EAPOL_START = 1
EAPOL_LOGOFF = 2

EAP_REQUEST = 1
EAP_RESPONSE = 2
EAP_SUCCESS = 3
EAP_FAILURE = 4

EAP_TYPE_ID = 1
EAP_TYPE_NOTE = 2
EAP_TYPE_MD5 = 4
EAP_TYPE_SHA1 = 20

CF_PATH ="/etc/ph3c.conf"

def getconf():
    cf = ConfigParser()
    if cf.read(CF_PATH):
      return dict(cf.items("config"))


def writeconf():
    cf = ConfigParser()
    cf.add_section("config")
    cf.set("config", "user", raw_input("Input username: "))
    cf.set("config", "pass", raw_input("Input password: "))
    cf.set("config", "dev", raw_input("Decice(eth0 by default): ") or "eth0")
    cf.set("config", "cmd", raw_input("Dhcp command(dhclient by default): ") or "dhclient")
    with open(CF_PATH,"w") as f:
        cf.write(f)
    print "Write conf success!"
    return getconf()


if len(sys.argv) ==2:
    if sys.argv[1] =="-r":
        writeconf()
        sys.argv[1] =1
    else:
        print "usage: sudo python ph3c.py"
        print "or rewrite config file by '-r'"
        sys.exit()

### Packet builders

def EAPOL(type, payload=""):
    return pack("!BBH", EAPOL_VERSION, type, len(payload))+payload

def EAP(code, id, type=0, data=""):
    if code in [EAP_SUCCESS, EAP_FAILURE]:
        return pack("!BBH", code, id, 4)
    else:
        return pack("!BBHB", code, id, 5+len(data), type)+data

def ethernet_header(src, dst, type):
    return dst+src+pack("!H",type)

def daemonize():
    try:
        pid = os.fork()
        if pid:
            sys.exit(0)
        os.chdir('/')
        os.umask(0)
        os.setsid()
        _pid = os.fork()
        if _pid:
            sys.exit(0)
    except OSError, e: 
        sys.stderr.write("fork #1 failed: (%d) %s\n" % (e.errno, e.strerror) )
        sys.exit(1)

    sys.stdout.flush()
    sys.stderr.flush()
    with open('/dev/null') as read_null, open('/dev/null', 'w') as write_null:
        os.dup2(read_null.fileno(), sys.stdin.fileno())
        os.dup2(write_null.fileno(), sys.stdout.fileno())
        os.dup2(write_null.fileno(), sys.stderr.fileno())

### Main program
CONF = getconf() or writeconf()

s=socket(AF_PACKET, SOCK_RAW, htons(ETHERTYPE_PAE))
s.bind((CONF["dev"], ETHERTYPE_PAE))

mymac=s.getsockname()[4]
llhead=ethernet_header(mymac, PAE_GROUP_ADDR, ETHERTYPE_PAE)


print "--> Sent EAPOL Start"
s.send(llhead+EAPOL(EAPOL_START))

IS = True
try:
    while True:
        p = s.recv(1600)[14:]
        vers,type,eapollen  = unpack("!BBH",p[:4])
        if type == EAPOL_EAPPACKET:
            code, id, eaplen = unpack("!BBH", p[4:8])
            if code == EAP_SUCCESS:
                print "Got EAP Success"
                call([CONF["cmd"], CONF["dev"]])
                daemonize()
                IS = False
                print ""
            elif code == EAP_FAILURE:
                print "Got EAP Failure"
                IS = True
            elif code == EAP_RESPONSE:
                print "?? Got EAP Response"
            elif code == EAP_REQUEST:
                reqtype = unpack("!B", p[8:9])[0]
                reqdata = p[9:4+eaplen]
                if reqtype == EAP_TYPE_ID and IS:
                    print "Got EAP Request for identity"
                    s.send(llhead+EAPOL(EAPOL_EAPPACKET,EAP(EAP_RESPONSE,id,reqtype,CONF["user"])))
                    print "--> Sent EAP response with identity %s." % CONF["user"]
                elif reqtype == EAP_TYPE_NOTE:
                    print "Got EAP_TYPE_NOTE"
                    s.send(llhead+EAPOL(EAPOL_EAPPACKET, EAP(EAP_RESPONSE, id, reqtype, "\x01\x16\x00\x7b\x49\x33\x60\x4f\x45\x78\x75\x01\x7c\x7f\x7b\x33\x69\x65\x57\x61\x75\x48\x02\x16\x31\x04\x59\x56\x6e\x52\x4d\x7e\x69\x31\x4d\x4f\x43\x33\x69\x65\x57\x61\x75\x48")))
                    print "--> Send EAP response with Notification"
                elif reqtype == EAP_TYPE_MD5:
                    print "Got EAP Request for MD5 challenge"
                    challenge=pack("!B",id)+CONF["pass"]+reqdata[1:]
                    resp=md5(challenge).digest()
                    resp=chr(len(resp))+resp
                    s.send(llhead+EAPOL(EAPOL_EAPPACKET,EAP(EAP_RESPONSE,id,reqtype,resp)))
                    print "--> Send EAP response with MD5 challenge"
                elif reqtype == EAP_TYPE_SHA1:
                    resp = "\x00\x16\x20\x0d\xf0\xad\xba\x0d\xf0\xad\xba\x0d\xf0\xad\xba\x0d\xf0\xad\xba\x0d\xf0\xad\xba\x0d\xf0\xad\xba\x0d\xf0\xad\xba\x0d\xf0\xad\xba\x15\x04\x00\x00\x00\x00\x06\x07\x41\x48\x74\x4a\x4d\x32\x42\x50\x52\x58\x68\x31\x41\x58\x78\x2f\x65\x7a\x4e\x70\x5a\x56\x64\x68\x64\x55\x67\x3d\x20\x20" + CONF["user"]
                    s.send(llhead+EAPOL(EAPOL_EAPPACKET,EAP(EAP_RESPONSE,id,reqtype,resp)))


                else:
                    print "\033[1;33m?? Got unknown Request type (%i)\033[0m" % reqtype
            else:
                print "\033[1;33m?? Got unknown EAP code (%i)\033[0m " % code
        else:
            print "Got EAPOL type %i" % type


except KeyboardInterrupt:
    print "Interrupted by user"
    s.send(llhead+EAPOL(EAPOL_LOGOFF))
