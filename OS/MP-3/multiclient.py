#!/usr/bin/python

# This is the multi-threaded client.  This program should be able to run
# with no arguments and should connect to "127.0.0.1" on port 8765.  It
# should run a total of 1000 operations, and be extremely likely to
# encounter all error conditions described in the README.

import getopt
import socket
import sys
import random
from threading import Thread, Lock, Condition
import time

host = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
port = int(sys.argv[2]) if len(sys.argv) > 2 else 8765
toaddr = sys.argv[3] if len(sys.argv) > 3 else "nobody@example.com"
fromaddr = sys.argv[4] if len(sys.argv) > 4 else "nobody@example.com"

DEFAULT_TIMEOUT=10.0
MAX_MAIL_BOX_MSG=99999
RCV_BUF_SIZE=512
DEFAULT_TIMEOUT=10.0
CR_LF='\r\n'
MAX_THREAD_POOL=32
MSG_LIST=["This program is cool.", "Programming is fun.", "Operating system assignment.", "I'm going to send and wait."]
HOST_LIST= [" host0"," host1"," host2"," host3", " host4", " host5", " host6","invalidhost7"," invalid host8", " "]
MAIL_FROM= [" mailfrom0"," mailfrom1"," mailfrom2"," mailfrom3", " mailfrom4", " mailfrom5"," mailfrom6", "invalidmailfrom7", "invalid mailfrom8", ""]
RCPT_TO= [" rcptto0"," rcptto1"," rcptto2"," rcptto3", " rcptto4", " rcptto5"," rcptto6", "invalidrcptto7", " invalid rcptto8"," "]
THRESHOLD_UPPER=100
THRESHOLD_LOWER=5
CLIENT_LOG="client"

class CLIENT_WORKER(Thread):
    def __init__(self,id, pool):
        Thread.__init__(self)
        self.pool = pool
        self.rcv_msg = ""
        self.thread_id=id
        self.time_start =time.time()
        self.time_end =time.time()
        
    def run (self):
        while self.pool.get_task():
            self.gen_rand_traffic()
        exit      
    
    def stop(self):
        self.__stop = True

    def msg_send(self, msg):
        try:
            # print(msg)
            self.socket.send(msg.encode('utf-8'))
        except:
            # print("Connection Closed")
            self.socket.close()

    def complete_cmd(self):
            try :
                self.time_start = time.time()
                #Keep Receiving the message unless self.cr_lf is found  
                while self.rcv_msg.find(CR_LF) == -1:
                    self.time_end = time.time()
                    time_val = DEFAULT_TIMEOUT - (self.time_end -self.time_start)
                    if time_val <= 0:
                        raise "Timeout" 
                    self.socket.settimeout(time_val)
                    self.rcv_msg += self.socket.recv(RCV_BUF_SIZE)
                    #print("MSG %s" % self.rcv_msg) 
                    self.socket.settimeout(None) 
            except :
                    # print("Connection Closed")
                    self.socket.close()
            # Valid rcv_command
            msg_cmd = self.rcv_msg[0:self.rcv_msg.find(CR_LF)]
            self.rcv_msg = self.rcv_msg[self.rcv_msg.find(CR_LF)+len(CR_LF):]
                
            return ((msg_cmd.rstrip()).lstrip())

    def gen_rand_traffic (self):     
        #try:
            global host, port
            clientsocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket = clientsocket
            try :
                self.socket.connect((host, port))
            except :
                return     
            
            
            #Wait for  Welcome Message
            print(self.complete_cmd())
            
            
            # Probability of 5% Sending Zero HELO
            # Probability of 95% Sending ONE HELO
            # Probability of 95%*5% Sending TWO HELO 
            # HOST LIST  has 3/10 Invalid HOST 
            self.threshold = THRESHOLD_UPPER
            while random.randint(1,THRESHOLD_UPPER) < (self.threshold -THRESHOLD_LOWER):
                self.msg_send("HELO %s \r\n" % random.choice(HOST_LIST))
                # MSG From Server
                print (self.complete_cmd())
                self.threshold = THRESHOLD_LOWER+THRESHOLD_LOWER
            
            # Probability of 5% Closing Connection
            # Probability of 95% Sending ONE Mail per client
            # Probability of 95%*45% Sending TWO Mail per client
            self.threshold = THRESHOLD_UPPER
            while random.randint(1,THRESHOLD_UPPER) < (self.threshold -THRESHOLD_LOWER):
                # Probability of 5% Sending MAIL FROM
                # Probability of 95% Sending MAIL FROM
                # Probability of 95%*5% Sending TWO MAIL FROM 
                # MAIL LIST  has 3/10 Invalid MAIL FROM
                # Command given in lower Case 
                self.threshold = THRESHOLD_UPPER
                while random.randint(1,THRESHOLD_UPPER) < (self.threshold -THRESHOLD_LOWER):
                    self.msg_send("mail FrOM:%s \r\n" % random.choice(MAIL_FROM))
                    # MSG From Server
                    print (self.complete_cmd())
                    self.threshold = THRESHOLD_LOWER+THRESHOLD_LOWER
                
                # Probability of 5% Sending RCPT TO
                # Probability of 95% Sending RCPT TO
                # Probability of 95%*45% Sending TWO RCPT TO (Slightly More) 
                # RCPT LIST  has 3/10 Invalid RCPT TO 
                self.threshold = THRESHOLD_UPPER
                while random.randint(1,THRESHOLD_UPPER) < (self.threshold -THRESHOLD_LOWER):
                    self.msg_send("RCPT TO:%s\r\n" % random.choice(RCPT_TO))
                    # MSG From Server
                    print (self.complete_cmd())
                    self.threshold = THRESHOLD_UPPER/2
                # 
                # Send Random Data
                self.msg_send("DATA\r\n %s \r\n.\r.\n"% random.choice(MSG_LIST))
                print (self.complete_cmd())
                print (self.complete_cmd())
                
                self.threshold = THRESHOLD_UPPER/2
                
                
            # Close the socket.
            time.sleep(1)
            self.socket.close()
        # except :
        #   self.socket.close()


class CLIENT_POOL():
    def __init__(self, max_worker,max_msg):
        self.max_msg_send= max_msg
        self.msg_count = 0
        self.worker_list = []
        self.pool_lock = Lock()
        for i in range(max_worker):
            client_worker = CLIENT_WORKER(i, self)
            client_worker.start()
            self.worker_list.append(client_worker)
        
    def get_task(self):
        with self.pool_lock:
            self.msg_count +=1
            if  self.msg_count <= self.max_msg_send:
                return True
            else:
                return False
        
    def task_pend(self):
        for thr in self.worker_list:
            thr.join()


def send(socket, message):
    # In Python 3, must convert message to bytes explicitly.
    # In Python 2, this does not affect the message.
    socket.send(message.encode('utf-8'))

# Nested Mail from
def  test_case1():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((host, port))
    print(s.recv(500))    
    send(s, " HElO %s \r\n" %  socket.gethostname())
    print(s.recv(500))
    send(s, "mail FROM: %s \r\n" % toaddr)
    print(s.recv(500))
    send(s, "mail FROM: %s \r\n" % toaddr)
    print(s.recv(500))
    send(s, "RCPT TO: %s\r\n" % fromaddr)
    print(s.recv(500))
    send(s, "DATA\r\n My Program is awesome . \r\n.\r\n")
    print(s.recv(500))
    print(s.recv(500))

# NO SPCAE BETWEEN  CMD
def test_case2():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((host, port))
    print(s.recv(500))    
    send(s, " HElO %s \r\n" %  socket.gethostname())
    print(s.recv(500))
    send(s, " mail FROM:%s \r\n" % toaddr)
    print(s.recv(500))
    send(s, "RCPT TO: %s\r\n" % fromaddr)
    print(s.recv(500))
    send(s, "DATA\r\n My Program is awesome . \r\n.\r\n")
    print(s.recv(500))
    print(s.recv(500))
    s.close()

# Time Out Close connection
def test_case3():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((host, port))
    print(s.recv(500))    
    send(s, " HElO %s \r\n" %  socket.gethostname())
    s.close()

#  Duplicate helo
def test_case4():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((host, port))
    print(s.recv(500))    
    send(s, " HElO %s \r\n" %  socket.gethostname())
    print(s.recv(500))
    send(s, " HElO %s \r\n" %  socket.gethostname())
    print(s.recv(500))
    send(s, " mail FROM: %s \r\n" % toaddr)
    print(s.recv(500))
    send(s, "RCPT TO: %s\r\n" % fromaddr)
    print(s.recv(500))
    send(s, "DATA\r\n My Program is awesome . \r\n.\r\n")
    print(s.recv(500))
    print(s.recv(500))
    s.close()

# Invalid CMD
def test_case5():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((host, port))
    print(s.recv(500))    
    send(s, " DDDDDD %s \r\n" %  socket.gethostname())
    print(s.recv(500))
    send(s, "Helo :%s \r\n" % socket.gethostname())
    print(s.recv(500))
    send(s, " mail FROM: %s \r\n" % toaddr)
    print(s.recv(500))
    send(s, "RCPT TO: %s\r\n" % fromaddr)
    print(s.recv(500))
    send(s, "DATA\r\n My Program is awesome . \r\n.\r\n")
    print(s.recv(500))
    print(s.recv(500))
    s.close()
  
# bulk continuous Command  
def test_case6():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((host, port))
    i = 5
    print(s.recv(500))    
    send(s, "HELO %s \r\n" %  socket.gethostname())
    print(s.recv(500))
    while i:
        send(s, "mail FROM: %s \r\n" % toaddr)
        print(s.recv(500))
        send(s, "RCPT TO: %s\r\n" % fromaddr)
        print(s.recv(500))
        send(s, "DATA\r\n My Program is awesome . \r\n.\r\n")
        print(s.recv(500))
        print(s.recv(500))
        i=i-1
    s.close()
    
# Multiple  Receipt 
def test_case7():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((host, port))
    print(s.recv(500))    
    send(s, "Helo :%s \r\n" % socket.gethostname())
    print(s.recv(500))
    send(s, " mail FROM: %s \r\n" % toaddr)
    print(s.recv(500))
    send(s, "RCPT TO: %s\r\n" % fromaddr)
    print(s.recv(500))
    send(s, "RCPT TO: %s\r\n" % fromaddr)
    print(s.recv(500))
    send(s, "DATA\r\n My Program is awesome . \r\n.\r\n")
    print(s.recv(500))
    print(s.recv(500))
    s.close()

 # Invalid  Receipt 
def test_case8():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((host, port))
    print(s.recv(500))    
    send(s, "Helo :%s \r\n" % socket.gethostname())
    print(s.recv(500))
    send(s, " mail FROM: %s \r\n" % toaddr)
    print(s.recv(500))
    send(s, "RCPT TO: %s\r\n" % "aa aaa")
    print(s.recv(500))
    send(s, "RCPT TO: %s\r\n" % fromaddr)
    print(s.recv(500))
    send(s, "DATA\r\n My Program is awesome . \r\n.\r\n")
    print(s.recv(500))
    print(s.recv(500))
    s.close() 

# Wrong command sequence
def test_case9():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((host, port))
    print(s.recv(500))    
    send(s, "Helo :%s \r\n" % socket.gethostname())
    print(s.recv(500))
    send(s, " mail FROM: %s \r\n" % toaddr)
    print(s.recv(500))
    send(s, "RCPT TO: %s\r\n" % fromaddr)
    print(s.recv(500))
    send(s, "MAIL FROM: %s\r\n" % fromaddr)
    print(s.recv(500))
    send(s, "DATA\r\n My Program is awesome . \r\n.\r\n")
    print(s.recv(500))
    print(s.recv(500))
    s.close()
    
# Command Needed
def test_case10():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((host, port))
    print(s.recv(500))    
    send(s, "Helo :%s \r\n" % socket.gethostname())
    print(s.recv(500))
    send(s, "RCPT TO: %s\r\n" % fromaddr)
    print(s.recv(500))
    send(s, " mail FROM: %s \r\n" % toaddr)
    print(s.recv(500))
    send(s, "RCPT TO: %s\r\n" % fromaddr)
    print(s.recv(500))
    send(s, "DATA\r\n My Program is awesome . \r\n.\r\n")
    print(s.recv(500))
    print(s.recv(500))
    s.close()
def clientloop():
    
    test_case1();
    test_case2();
    test_case3();
    test_case4();
    test_case5();
    test_case6();
    test_case7();
    test_case8();
    test_case9();
    test_case10();
    pool= CLIENT_POOL(MAX_THREAD_POOL, MAX_MAIL_BOX_MSG)
    pool.task_pend()


    
# You don't have to change below this line.  You can pass command-line arguments
# -h/--host [IP] -p/--port [PORT] to put your server on a different IP/port.
opts, args = getopt.getopt(sys.argv[1:], 'h:p:', ['host=', 'port='])

for k, v in opts:
    if k in ('-h', '--host'):
        host = v
    if k in ('-p', '--port'):
        port = int(v)

print("Client coming up on %s:%i" % (host, port))
clientloop()


