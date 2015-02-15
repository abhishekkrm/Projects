from __future__ import with_statement
from threading import Thread, Lock

# This program simulates a postmodern game between two teams.  Each team
# presses their button as fast as they can.  There is a counter that starts at
# zero; the red team's increases a counter, while the blue team's button
# decreases the counter.  They each get to press their button 10000 times. If the
# counter ends up positive, the read team wins; a negative counter means the blue
# team wins.
#
# a. This game is boring: it should always end in a draw.  However, the provided
#    implementation is not properly synchronized.  When both threads terminate,
#    what are the largest and smallest possible scores?
# 
# Ans a).
#    Largest possible score  =  10000
#    Smallest possible score = -10000
#
# b. What other values can the score have when both threads have terminated?
#
# Ans b).  
#    Score can have any value between -10000 and 10000. [Including 10000 
#    and -10000]
#    Range of Score :
#    -10000 <= Score <= 10000
#
# c. Add appropriate synchronization such that updates to the counter
#    occur in a critical section, ensuring that the energy level is
#    always at 0 when the two threads terminate.
#
#    Your synchronization must still allow interleaving between the two threads.


counter = 0

# Lock to hold before updating counter
lock_counter = Lock()

class Button(Thread):
    def __init__(self):
        Thread.__init__(self)

    def run(self):
        global counter
        for i in range(10000):
            lock_counter.acquire()
            counter += 1
            lock_counter.release()           

class Team(Thread):
    def __init__(self):
        Thread.__init__(self)

    def run(self):
        global counter
        for j in range(10000):
            lock_counter.acquire()
            counter -= 1
            lock_counter.release()


w1 = Button()
w2 = Team()
w1.start()
w2.start()
w1.join()
w2.join()

print("The counter is " + str(counter))

##
## vim: ts=4 sw=4 et ai
##
