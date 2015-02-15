from threading import Thread, Lock
import time, random

# This problem models a speed dating application.  A matchmaker thread will
# repeatedly select two eligible bachelors and then let them meet for a few
# minutes to see if they have chemistry.
#
# A bachelor can only participate in one date at a time.
#
# Modify the following code to avoid deadlocks

bachelors = [Lock() for i in range(100)]

class Matchmaker(Thread):
    def __init__(self, id):
        Thread.__init__(self)
        self.id = id

    def run(self):
        while True:
            b1 = random.randrange(100)
            b2 = random.randrange(100)

            # you can't date yourself
            if b1 == b2:
                continue
            #
            # The problem here is one thread may be waiting for b2 which is 
            # locked by other thread and vice versa. For Example, lets say 
            # thread one is waiting for b2(10) with lock on b1(5) and thread
            # two may be waiting for b2(5) with lock on b1(10). This result 
            # in deadlock as none of the thread can make progress.
            # 
            # To avoid deadlock we need to make sure that resources are always 
            # acquired in well defined order.
            # Therefore by ensuring b1 < b2 (or b1 > b2) we can avoid deadlock.
            #
            # If b1 is more than b2 then swap so that b1 always less than b2.
            #
            if b1 > b2:
                b1,b2 = b2,b1

            bachelors[b1].acquire()
            bachelors[b2].acquire()

            # check for chemistry (which apparently involves sleeping)
            print ("matchmaker %i checking bachelors %i and %i" % (self.id, b1, b2))
            time.sleep(0.1)

            bachelors[b1].release()
            bachelors[b2].release()


for i in range(20):
    Matchmaker(i).start()


##
## vim: ts=4 sw=4 et ai
##
