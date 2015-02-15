#!/usr/bin/python
import sys
import socket
import datetime
import time

host = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
port = int(sys.argv[2]) if len(sys.argv) > 2 else 8765
toaddr = sys.argv[3] if len(sys.argv) > 3 else "nobody@example.com"
fromaddr = sys.argv[4] if len(sys.argv) > 4 else "nobody@example.com"

def send(socket, message):
    # In Python 3, must convert message to bytes explicitly.
    # In Python 2, this does not affect the message.
    socket.send(message.encode('utf-8'))

def sendmsg(msgid, hostname, portnum, sender, receiver):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((hostname, portnum))

    print(s.recv(500))
    
    send(s, " HElO %s \r\n" % socket.gethostname())
    print(s.recv(500))

    send(s, " mail FROM:%s \r\n" % sender)
    print(s.recv(500))
    
    send(s, " mail FROM: %s \r\n" % sender)
    print(s.recv(500))
    
    send(s, "RCPT TO: %s\r\n" % receiver)
    print(s.recv(500))

    send(s, "DATA\r\n My Program is awesome . \r\n.\r\n")
    print(s.recv(500))
    print(s.recv(500))

for i in range(1, 3):
    sendmsg(i, host, port, fromaddr, toaddr)
