from threading import Thread, Lock, Condition
import time
import random

# This program simulates interaction of applications with the outside world.
#
# Applications wait for specific input events, which are modeled here by numbers
# between 0 and 10.  Periodically, the outside world provides input to the
# system.  In a real processor these would cause interrupts, but here we model
# them as calls to the input_ready function.
#
# Implement the Scheduler monitor below using python Locks and
# Condition variables.


NUM_APPS = 10
# Possible Range
RANGE=10

def delay():
    """sleep for a random interval"""
    time.sleep(random.randint(0, 2))

class Scheduler(object):
    def __init__(self):
        # Scheduler Lock
        self.schedule_lock = Lock()
        self.wait_input = [] * RANGE 
        self.avail_input = [] * RANGE
        self.input_cond = []
        for i in range(RANGE):
            self.input_cond.append(Condition(self.schedule_lock))
        pass

    def input_ready(self, input_number):
        """wakes up any applications waiting for the given input"""
        with self.schedule_lock:
           if input_number in self.wait_input:
               self.avail_input.append(input_number)
               self.wait_input.remove(input_number)
               self.input_cond[input_number].notify()
        pass

    def wait_for_input(self, input_number):
        """blocks the current application until input_number becomes available"""
        with self.schedule_lock:
            self.wait_input.append(input_number)
            while input_number not in self.avail_input:
                self.input_cond[input_number].wait()
            self.avail_input.remove(input_number)
        pass

class TheOutsideWorld(Thread):

    def __init__(self, scheduler):
        Thread.__init__(self)
        self.scheduler = scheduler

    def run(self):
        while True:
            delay()
            input_number = random.randrange(10)
            print ("input %d is available" % input_number)
            self.scheduler.input_ready(input_number)

class Application(Thread):
    def __init__(self, scheduler, id):
        Thread.__init__(self)
        self.scheduler = scheduler
        self.id        = id

    def run(self):
        print ("application %d: starting" % self.id)
        for i in range(random.randrange(15)):
            input_number = random.randrange(10)
            print("application %d: waiting for input %i" % (self.id, input_number))
            self.scheduler.wait_for_input(input_number)
            print("application %d: got input, continuing" % self.id)
        print("application %d: done" % self.id)

scheduler = Scheduler()
for i in range(NUM_APPS):
    Application(scheduler, i).start()
TheOutsideWorld(scheduler).start()

##
## vim: ts=4 sw=4 et ai
##
