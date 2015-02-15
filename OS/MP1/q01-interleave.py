from threading import Thread

# a. Run the following concurrent program. Are there any particular patterns in
#    the output? Is the interleaving of the output from the two threads
#    predictable in any way?
#
# Ans a).
#    No, there is no particular pattern in the output. Also, there is no 
#    predictabilty in the output from the two thread.
# 
# b. If the answer to part (a) is affirmative, run the same program while
#    browsing the web. Does the pattern you outlined in section (a) hold?
#
# Ans b).
#    The pattern is not predictable and is different each time the program is 
#    run.
#
# c. In general, can one rely on a particular timing/interleaving of executions
#    of concurrent processes?
# 
# Ans c).
#    We cannot rely on a particular timing/interleaving of executions of 
#    concurrent processes.
#
# d. Given that there are no synchronization operations in the code below, any
#    interleaving of executions should be possible. When you run the code, do
#    you believe that you see a large fraction of the possible interleavings? If
#    so, what do you think makes this possible? If not, what does this imply
#    about the effectiveness of testing as a way to find synchronization errors?
#
# Ans d).
#    Yes, we see large fraction of the possible interleavings. The Operating
#    system is making this possible by scheduling the processes in and out. 
#
class Worker1(Thread):
    def __init__(self):
        Thread.__init__(self)

    def run(self):
        while True:
            print("Hello from Worker 1")

class Worker2(Thread):
    def __init__(self):
        Thread.__init__(self)

    def run(self):
        while True:
            print("Hello from Worker 2")

w1 = Worker1()
w2 = Worker2()
w1.start()
w2.start()

##
## vim: ts=4 sw=4 et ai
##

