from threading import Thread, Lock, Condition
import time, random

# This problem simulates a simplified map/reduce controller.  A map/reduce
# controller performs a computation in two steps.  In the first step (the "map
# phase"), each input value is transformed (by a separate worker thread) into
# an intermediate value.  In the second step (the "reduce phase"), all of the
# intermediate values are combined (by the worker threads) to form an output.
#
# Thus all of the worker threads start the map phase simultaneously, but none
# can proceed to the reduce phase until they have all completed the map phase.
# they will then all start the reduce phase, but cannot start another map/reduce
# computation until they have all completed the reduce phase.
#
# Implement the controller monitor using python Lock and Condition variables

def delay():
    """sleep for a random interval"""
    time.sleep(random.randint(0, 2))

class Controller(object):

    def __init__(self, num_workers):
        # Max Number of worker
        self.max_worker = num_workers
        # Current Enter Worker Number
        self.enter_worker = 0
        # Current Left Worker Number
        self.leave_worker = 0
        self.barrier_lock = Lock()
        self.enter_barrier = Condition(self.barrier_lock)
        self.leave_barrier = Condition(self.barrier_lock)
        pass

    def start_next_phase(self):
        """Called by a thread to indicate that it has completed the current
        phase.  Function blocks until all threads have completed the current
        phase."""
        with self.barrier_lock:
            self.enter_worker = (self.enter_worker + 1)
            # Let other thread to catch up.
            if self.enter_worker < self.max_worker:
                while self.enter_worker < self.max_worker:
                    self.enter_barrier.wait()
            else :
                self.leave_worker = 0
                self.enter_barrier.notify_all()
            
            self.leave_worker = (self.leave_worker + 1)
            # Let other thread to catch up.
            if self.leave_worker < self.max_worker:
                while self.leave_worker < self.max_worker:
                    self.leave_barrier.wait()
            else :
                self.enter_worker = 0
                self.leave_barrier.notify_all()
        pass

class Worker(Thread):

    def __init__(self, controller, id):
        Thread.__init__(self)
        self.controller = controller
        self.id         = id

    def run(self):
        while True:
            # wait for start of map phase:
            print("worker #%d: waiting for input" % self.id)
            self.controller.start_next_phase()
            # perform map phase
            print("worker #%d: starting map phase" % self.id)
            delay()
            print("worker #%d: finished map phase" % self.id)
            # wait for start of reduce phase
            self.controller.start_next_phase()
            # perform reduce phase
            print("worker #%d: starting reduce phase" % self.id)
            delay()
            print("worker #%d: finished reduce phase" % self.id)
            self.controller.start_next_phase()
            print("worker #%d: computation done" % self.id)


if __name__ == '__main__':
    num_threads = 10
    controller  = Controller(num_threads)
    for i in range(num_threads):
        Worker(controller,i).start()

##
## vim: ts=4 sw=4 et ai
##
