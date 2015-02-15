from threading import Thread, Semaphore
import time
import random

# a. Complete the implementation of the OneLaneBridge class below using
#    python semaphores.  Your implementation should be able to make prograss if
#    there are any cars that can cross.
#
# b. What fairness properties does your implementation have?  Under what
#    conditions (if any) can a thread starve?
#
# Ans b).
#    If there is no traffic on the bridge the implemetation is fair enough to 
#    select car either going in south or north direction (i.e. selection of car 
#    is not biased on direction). Also there is no deadlock with the suggested
#    Semaphore solution.
#    The thread (car) can starve if the car going to a certain direction keeps
#    coming in that case the car travelling in oposite direction will not get
#    a chance to cross the bridge unless the bridge is free.
#

north = 0
south = 1

class OneLaneBridge(object):
    """
    A one-lane bridge allows multiple cars to pass in either direction, but at any
    point in time, all cars on the bridge must be going in the same direction.

    Cars wishing to cross should call the cross function, once they have crossed
    they should call finished()
    """

    def __init__(self):
        # Semaphore for mutual exclusion
        self.mutex = Semaphore(1)
        # Semaphore for North/South waiting Cars.
        self.waiting = [Semaphore(0), Semaphore(0) ]
        # No of North/South direction waiting Car
        self.waiting_car = [ 0, 0 ]
        self.wait = 0
        # Number of cars on the bridge.
        self.car_on_bridge = 0
        # Current direction of traffic on bridge 
        # -1 indicates no traffic on bridge.
        #  0 indicates direction of traffic is north.
        #  1 indicates direction of traffic is south.
        self.traffic_cur_direction = -1
        pass

    def cross(self,direction):
        """wait for permission to cross the bridge.  direction should be either
        north (0) or south (1)."""
        # TODO
        self.mutex.acquire()
        self.wait = 0
        if self.car_on_bridge != 0 and self.traffic_cur_direction != direction:
            self.waiting_car[direction] += 1
            self.wait = 1
        else:
            self.waiting_car[direction] = 0
            self.car_on_bridge = self.car_on_bridge + 1;
            self.traffic_cur_direction = direction
        self.mutex.release()
        # If Wait then P
        if self.wait:
            self.waiting[direction].acquire()
        pass

    def finished(self,direction):
        # 
        if  direction == south:
            reverse_dir = north
        else:
            reverse_dir = south
        
        self.mutex.acquire()
        self.car_on_bridge = self.car_on_bridge - 1
        if self.car_on_bridge == 0:
            if self.waiting_car[reverse_dir] != 0:
                self.car_on_bridge = self.waiting_car[reverse_dir]
                self.traffic_cur_direction = reverse_dir
                for i in range(self.waiting_car[reverse_dir]):
                    # Signal V
                    self.waiting[reverse_dir].release()
                self.waiting_car[reverse_dir] = 0
            else:
                self.traffic_cur_direction = -1;
        self.mutex.release()
        pass


class Car(Thread):
    def __init__(self, bridge, car_id):
        Thread.__init__(self)
        self.direction = random.randrange(2)
        self.wait_time = random.uniform(0.1,0.5)
        self.bridge    = bridge
        self.car_id    = car_id

    def run(self):
        # drive to the bridge
        time.sleep(self.wait_time)
        print "Car %d: Trying to cross %s" % (self.car_id, "south" if self.direction else "north")
        # request permission to cross
        self.bridge.cross(self.direction)
        print "Car %d: Crossing" % self.car_id
        # drive across
        time.sleep(0.01)
        print "Car %d: Crossed" % self.car_id
        # signal that we have finished crossing
        self.bridge.finished(self.direction)
        print "Car %d: Finished crossing" % self.car_id


if __name__ == "__main__":

    judd_falls = OneLaneBridge()
    for i in range(100):
        Car(judd_falls, i).start()

##
## vim: ts=4 sw=4 et ai
##
