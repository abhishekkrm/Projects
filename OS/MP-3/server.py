#!/usr/bin/python

import getopt
import socket
import sys
from threading import Thread, Lock, Condition
import shutil
import time

# STOP!  Don't change this.  If you do, we will not be able to contact your
# server when grading.  Instead, you should provide command-line arguments to
# this program to select the IP and port on which you want to listen.  See below
# for more details.
host = "127.0.0.1"
port = 8765

# Global Variables
NETID="am2633"
RCV_BUF_SIZE=512
DEFAULT_TIMEOUT=10.0
MAX_THREAD_POOL=32
MAILBOX_FILE="mailbox"
MAILBOX_BATCH=32
NO_OF_SNMP_STATE=6
CR_LF='\r\n'
WELCOME_MSG="220 " + NETID + " SMTP CS4410MP3 \r\n" 
END_DATA_MSG="354 End data with <CR><LF>.<CR><LF \r\n>"
OK_MSG="250 OK\r\n"

RET_ERR=-1
ERR_TIMEOUT="421 4.4.2" + NETID + " Error: timeout exceeded \r\n"
ERR_DUP_HELO ="503 Error: duplicate HELO \r\n"
ERR_HELO_SYNTAX="501 Syntax:  HELO yourhostname \r\n"
ERR_CMD="500 Error: command not recognized \r\n"
ERR_SYNTAX="500 Error: bad syntax \r\n"
ERR_NESTED_MAIL="503 Error: nested MAIL command \r\n"
ERR_MAILFROM_SYNTAX="501 Syntax: MAIL FROM: email_address \r\n"
ERR_RCPTTO_SYNTAX="501 Syntax: MAIL TO: email_address \r\n"
ERR_SYNTAX_HELO="503 Error: need HELO command \r\n"

class SNMP_STATE:
    INITIAL, HELO, MAILFROM, RCPTTO, DATA, CLOSED = range(NO_OF_SNMP_STATE)

# handle a single client request
class ConnectionHandler:
    def __init__(self, socket):
        self.socket = socket
        self.rcv_msg = ""
        self.snmp_state = SNMP_STATE.INITIAL
        self.mail_from = ""
        self.rcpt_to = []
        self.data = ""
        self.client_hostname = ""
        self.idx = 1
        self.conn_open = True
        self.time_start = time.time()
        
    def timeout_handler(self):
        try :
            self.socket.settimeout(DEFAULT_TIMEOUT)
            self.socket.send(ERR_TIMEOUT.encode('utf-8'))
            self.socket.timeout(None)
        except:
            self.socket.close()
        self.socket.close()
        self.snmp_state = SNMP_STATE.CLOSED
        self.conn_open = False
        return
    
    def processed_data(self):
            try :
                #Keep Receiving the message unless self.cr_lf is found  
                while self.rcv_msg.find(CR_LF+"."+CR_LF) == -1:
                    self.time_end = time.time()
                    time_val = DEFAULT_TIMEOUT - (self.time_end -self.time_start)
                    if time_val <= 0:
                        raise "Timeout" 
                    self.socket.settimeout(time_val)
                    self.rcv_msg += self.socket.recv(RCV_BUF_SIZE)
                    if not self.rcv_msg:
                        raise "Close"
                    self.socket.settimeout(None) 
            except:
                self.timeout_handler()
            # Valid rcv_command
            data = self.rcv_msg[0:self.rcv_msg.find(CR_LF+"."+CR_LF)]
            self.rcv_msg = ""
            #print("MSG %s" % msg_cmd)      
            return ((data.rstrip()).lstrip())

    # Wait  unless we receive full command
    def complete_cmd(self):
            try :
                #Keep Receiving the message unless self.cr_lf is found  
                while self.rcv_msg.find(CR_LF) == -1:
                    self.time_end = time.time()
                    time_val = DEFAULT_TIMEOUT - (self.time_end -self.time_start)
                    if time_val <= 0:
                        raise "Timeout"
                    self.socket.settimeout(time_val)
                    self.rcv_msg += self.socket.recv(RCV_BUF_SIZE)
                    if not self.rcv_msg:
                        raise "Close"
                    #print("MSG %s" % self.rcv_msg) 
                    self.socket.settimeout(None)
            except:
                self.timeout_handler()
            # Valid rcv_command
            msg_cmd = self.rcv_msg[0:self.rcv_msg.find(CR_LF)]
            self.rcv_msg = self.rcv_msg[self.rcv_msg.find(CR_LF)+len(CR_LF):]
            
            return ((msg_cmd.rstrip()).lstrip())

    def StringCompare(self, s1, s2):
        try:
            return s1.lower() == s2.lower()
        except AttributeError:
            return False

    def msg_send(self, msg):
        try:
            self.socket.send(msg.encode('utf-8'))
        except:
            self.socket.close()
            self.snmp_state = SNMP_STATE.CLOSED
            self.conn_open = False
        
        
    def is_valid_cmd(self, words):
        ret_val=0
        if len(words) != 0:
            if not ((self.StringCompare(words[0],"HELO" )) or
                (len(words)>1 and (self.StringCompare([words[0]+" "+words[1]][0],"MAIL FROM:"))) or 
                (len(words)>1 and (self.StringCompare([words[0]+" "+words[1]][0],"RCPT TO:")))  or 
                (self.StringCompare(words[0],"DATA" ))) :           
                ret_val = RET_ERR
                self.msg_send(ERR_CMD)
        else:
            ret_val = RET_ERR
            self.msg_send(ERR_SYNTAX)
        return ret_val    
        
    def is_valid_next_state(self, words):
        ret_val = 0
        if(self.snmp_state == SNMP_STATE.HELO):
            if len(words) != 2:
                self.msg_send(ERR_HELO_SYNTAX)
                ret_val = RET_ERR
        else:
            if (len(words)>= 1 and self.StringCompare(words[0],"HELO")):
                self.msg_send(ERR_DUP_HELO)
                ret_val = RET_ERR
        
        if ret_val == 0: 
            if(self.snmp_state == SNMP_STATE.RCPTTO):
                if(len(words)>1 and (self.StringCompare([words[0]+" "+words[1]][0],"MAIL FROM:"))):
                    self.msg_send(ERR_NESTED_MAIL)
                    ret_val = RET_ERR
        return ret_val;   
    
    def helo_validate(self, words, msg_cmd):
        # print ("helo_validate %s" % words)   
        ret_val = self.is_valid_cmd(words)
        if ret_val == 0:
            ret_val = self.is_valid_next_state(words)
        if ret_val == 0:
            if not (self.StringCompare(words[0],"HELO")):
                self.msg_send(ERR_SYNTAX_HELO)
                ret_val=RET_ERR
        return (ret_val)

    def mailfrom_validate(self, words, msg_cmd):
        # print ("mailfrom_validate %s" % words)
        ret_val = self.is_valid_cmd(words)
        if ret_val == 0:
            ret_val = self.is_valid_next_state(words)    
        if ret_val == 0:
            if not (len(words)>1 and (self.StringCompare([words[0]+" "+words[1]][0],"MAIL FROM:"))):
                self.msg_send("503 Error: need " + "MAIL FROM:" + " command \r\n")
                ret_val=RET_ERR
        if ret_val == 0:
            if len(words) == 4:
                self.msg_send("555 <"+ msg_cmd[msg_cmd.find(":")+1:]+ ">: Sender address rejected \r\n")
                ret_val=RET_ERR
            elif len(words) !=3:
                self.msg_send(ERR_MAILFROM_SYNTAX)
                ret_val=RET_ERR
        return (ret_val)
        
        
    def rcptto_validate(self, words, msg_cmd):
        # print ("rcptto_validate %s" % words)
        ret_val = self.is_valid_cmd(words)
        if ret_val == 0:
            ret_val = self.is_valid_next_state(words)    
        if ret_val == 0:
                if (self.StringCompare(words[0],"DATA" )):
                    ret_val = 1
                else:
                    if len(words) == 4:
                        self.msg_send("555 <"+ msg_cmd[msg_cmd.find(":")+1:]+ ">: Recipient address invalid \r\n")
                        ret_val=RET_ERR
                    elif len(words) !=3:
                        self.msg_send(ERR_RCPTTO_SYNTAX)
                        ret_val=RET_ERR
        return (ret_val)
        
    def validate_cmd(self, msg_cmd):
            #print (msg_cmd)
#       try:
            ret_val = 0
            val=""
            if self.snmp_state == SNMP_STATE.HELO:
                words = msg_cmd.split()
                #print (words)
                ret_val = self.helo_validate(words, msg_cmd)
                if ret_val == 0:
                    val= msg_cmd.split()[1]
                return (ret_val , val)
            elif self.snmp_state == SNMP_STATE.MAILFROM:
                words = msg_cmd.split()
                ret_val = self.mailfrom_validate(words, msg_cmd)
                if ret_val == 0:
                    val= msg_cmd.split(":")[1]
                return (ret_val , val)
            elif self.snmp_state == SNMP_STATE.RCPTTO:
                words = msg_cmd.split()
                ret_val = self.rcptto_validate(words, msg_cmd)
                if ret_val == 0:            
                    val = msg_cmd.split(":")[1]
                return (ret_val , val)
            return ret_val
#        except:
#            return RET_ERR
    
    def handle_helo(self):
        self.time_start = time.time()
        ret_val = 0
        while SNMP_STATE.HELO == self.snmp_state and self.conn_open:
            msg_cmd = self.complete_cmd()
            if not self.conn_open:
                continue;               
            (ret_val, val) = self.validate_cmd(msg_cmd)
            if ret_val == 0:
                msg_send = "250 " + NETID + "\n" 
                self.client_hostname = val
                self.msg_send(msg_send)
                if not self.conn_open:
                    continue;
                self.snmp_state = SNMP_STATE.MAILFROM

    def handle_mailfrom(self):
        self.time_start = time.time()
        ret_val = 0
        
        while SNMP_STATE.MAILFROM == self.snmp_state and self.conn_open:
            msg_cmd = self.complete_cmd()
            if not self.conn_open:
                continue;  
            (ret_val, val) = self.validate_cmd(msg_cmd)
            if ret_val == 0:
                self.mail_from = val
                self.msg_send(OK_MSG)
                if not self.conn_open:
                    continue;  
                self.snmp_state = SNMP_STATE.RCPTTO

    def handle_rcptto(self):
        self.time_start = time.time()
        ret_val = 0
        while SNMP_STATE.RCPTTO == self.snmp_state and self.conn_open:
            msg_cmd = self.complete_cmd()
            if not self.conn_open:
                continue;
            (ret_val, val) = self.validate_cmd(msg_cmd)
            if ret_val == 0:
                self.rcpt_to.append(val)
                ret_val = self.msg_send(OK_MSG)
                if not self.conn_open:
                    continue;
            elif ret_val == 1:
                    self.msg_send(END_DATA_MSG)
                    if not self.conn_open:
                        continue;
                    self.snmp_state = SNMP_STATE.DATA
                                
    def handle_data(self):
        self.start = time.time()
        while SNMP_STATE.DATA == self.snmp_state and self.conn_open:
            (data) = self.processed_data()
            if not self.conn_open:
                continue;  
            self.data = data
            msg_send = OK_MSG + ":  delivered message " + str(self.idx)
            self.msg_send(msg_send)
            if not self.conn_open:
                continue;
            self.err_lastobserved = 0
            self.snmp_state = SNMP_STATE.MAILFROM
                        
    def handle_conection(self, wrk):
        self.client_hostname = ""
        self.idx = 1
        self.conn_open = True
        self.err_lastobserved = 0
        self.msg_send(WELCOME_MSG)
        if self.conn_open:
            self.snmp_state = SNMP_STATE.HELO
            self.handle_helo()
            while self.conn_open :
                self.mail_from = ""
                self.rcpt_to = []
                self.data = ""
                self.handle_mailfrom()
                self.handle_rcptto()
                self.handle_data()
                if self.conn_open:
                    wrk.pool.mail.create_mail(self)
                    self.idx += 1
                self.snmp_state = SNMP_STATE.MAILFROM

                


class SMTPBACKUP_WORKER(Thread):
    def __init__(self, mail):
        Thread.__init__(self)
        self.mail = mail
    
    # BackUP Thread Start
    def run(self):
        #print ("SMTP BACKUP WORKER STARTED")
        while True:
            self.mail.backup_task()          
    
    # BackUP Thread Stop
    def stop(self):
        #print ("SMTP BACKUP WORKER STOPPED")
        self.__stop = True
        
# Monitor Implementation for MailBox
class MAILBOX():
    def __init__(self, mailbox_file):
        self.mailbox_file = mailbox_file
        self.mail_id = 1 
        self.lastmail_backupid= 0
        # Create a File
        self.file = open(self.mailbox_file+".txt",'w')
        self.file.close()
        self.mailbox_lock = Lock()
        self.backup_needed = Condition(self.mailbox_lock)
        self.smtpbackup_worker = SMTPBACKUP_WORKER(self)
        self.smtpbackup_worker.start()

    def create_mail(self, ct):
        mail_msg = ""
        #Create Header
        mail_msg += "Received: from " + ct.client_hostname + " by " + NETID + " (CS4410MP3) \n"
        mail_msg += "Number:" + str(self.mail_id) + "\n"
        mail_msg += "From:" + ct.mail_from + "\n"
        while ct.rcpt_to:
            rcpt = ct.rcpt_to.pop(0)
            mail_msg += "To:" + rcpt + "\n"
        mail_msg += "\n"
        mail_msg += ct.data + "\n\n"
        # print (mail_msg)
        self.mail_recive(mail_msg)

    # Mail BackUP Task
    def backup_task(self):
        with self.mailbox_lock:
            while self.mail_id - self.lastmail_backupid <= MAILBOX_BATCH:
                self.backup_needed.wait()  
            new_mailfile = MAILBOX_FILE + str(self.lastmail_backupid+1) + \
                "-" + str(self.lastmail_backupid+MAILBOX_BATCH) + ".txt"
            shutil.copy(MAILBOX_FILE + ".txt", new_mailfile)
            self.lastmail_backupid += MAILBOX_BATCH
            self.file = open(MAILBOX_FILE + ".txt",'w')
            self.file.close()
    
    # Mail Receive Store and notify backup thread        
    def mail_recive(self, mail_msg):
        with self.mailbox_lock:
            self.file = open(self.mailbox_file+".txt",'a')
            self.file.write(mail_msg)
            self.file.close()
            self.mail_id += 1
            if self.mail_id - self.lastmail_backupid > MAILBOX_BATCH:
                self.backup_needed.notify()
    
    # Stop BackUp Thread    
    def stop_backup(self):
        self.smtpbackup_worker.stop()


class SMTPSERVER_WORKER(Thread):
    def __init__(self, thread_id, pool):
            Thread.__init__(self)
            self.pool = pool
            self.thread_id = thread_id

    # Stop SMTP SERVER WORKER                
    def run(self):
        #print ("SMTP SERVER WORKER %d STARTED " % self.thread_id)
        while True:
            ct = self.pool.remove_connection()
            # FIXME
            ct.handle_conection(self)
            self.pool.connection_closed()
            
    # Stop SMTP SERVER WORKER       
    def stop(self):
        #print ("SMTP SERVER WORKER %d STOPPED" % self.thread_id)
        self.__stop = True
        
# Monitor Implementation of SMTP SERVER POOL
class SMTPSERVER_POOL():
    def __init__(self, max_worker ,mailbox):
        self.cur_connection = 0
        self.conn_list=[]
        self.mail = mailbox 
        self.worker_list = []
        self.smtpserver_list_lock = Lock()
        self.smtpserver_count_lock = Lock()
        self.conn_list_empty = Condition(self.smtpserver_list_lock)
        self.can_handle_conn = Condition(self.smtpserver_count_lock)
        for i in range(max_worker):
            smtp_worker = SMTPSERVER_WORKER(i, self)
            smtp_worker.start()
            self.worker_list.append(smtp_worker)

    # Wait if connection not ready else return socket to handle
    def remove_connection(self): 
        with self.smtpserver_list_lock:
            # Check whether connection is ready
            while len(self.conn_list) == 0:
                self.conn_list_empty.wait()
        # Pop element from the begin
        return  self.conn_list.pop(0)
        
    # Add Connection to connection list              
    def add_connection(self, conn_handler):
        with self.smtpserver_list_lock:
            # Add Element at the End
            self.conn_list.append(conn_handler)
            self.conn_list_empty.notify()


    # Start connection in the list        
    def connection_start(self):
        with self.smtpserver_count_lock:
            self.cur_connection += 1
            while self.cur_connection > MAX_THREAD_POOL:
                self.can_handle_conn.wait();

                 
    # End connection from the list            
    def connection_closed(self):
        with self.smtpserver_count_lock:
            self.cur_connection -= 1
            self.can_handle_conn.notify();

    
    #Stop Thread Pool          
    def stop_pool(self):
        while self.worker_list:
            smtp_worker = self.worker_list.pop(0)
            smtp_worker.stop()
                           
# The main server loop
def serverloop():
    # Create MailBox
    mailbox = MAILBOX(MAILBOX_FILE)
    # Create Thread Pool   
    pool = SMTPSERVER_POOL(MAX_THREAD_POOL, mailbox)
    serversocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # mark the socket so we can rebind quickly to this port number
    # after the socket is closed
    serversocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    # bind the socket to the local loopback IP address and special port
    serversocket.bind((host, port))
    # start listening with a backlog of 5 connections
    serversocket.listen(5)

    while True:
        try:
            # Start connection wait if pool reaches the capacity
            pool.connection_start()
            # accept a connection
            (clientsocket, address) = serversocket.accept()
            ct = ConnectionHandler(clientsocket)
            pool.add_connection(ct)
            
        except KeyboardInterrupt:
            #print("\n Server Terminated")
            pool.stop_pool()
            mailbox.stop_backup()
            serversocket.close()
            sys.exit()

# You don't have to change below this line.  You can pass command-line arguments
# -h/--host [IP] -p/--port [PORT] to put your server on a different IP/port.
opts, args = getopt.getopt(sys.argv[1:], 'h:p:', ['host=', 'port='])

for k, v in opts:
    if k in ('-h', '--host'):
        host = v
    if k in ('-p', '--port'):
        port = int(v)

print("Server coming up on %s:%i" % (host, port))
serverloop()
