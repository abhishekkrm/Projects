import argparse
from threading  import Thread
import time
import sys
import random
from subprocess import Popen

# In this question you will explore the performance impact of spreading tasks
# across multiple threads and processes.   This program always executes N
# independent tasks, but it spreads the work among varying numbers of threads
# and processes.
#
# You can run this program in many ways:
#
# python q03-timing.py cpu sequential
#    runs N cpu-bound jobs sequentially
#
# python q03-timing.py cpu threaded k
#    runs N cpu-bound jobs using k threads
#
# python q03-timing.py cpu forked k
#    runs N cpu-bound jobs using k subprocesses
#
# python q03-timing.py io (sequential/threaded/forked) ...
#    as above, but execute I/O bound jobs
#
# Complete the following tasks (submit your plots and explanations in a pdf
# file)
#
# a. Sketch a hypothesized plot containing three curves for the I/O bound task:
#
#  - total run time of the threaded implementation against number of threads
#  - total run time of the multi-process implementation against the number of
#    processes
#  - total run time of a sequential implementation that runs in a single thread
#
#    Be sure to explain why you drew the curves the way you did.  For example,
#    you might note that the sequential version doesn't depend on the number of
#    threads, so it should be a flat line.
#
# b. Hypothesize and sketch the same set of curves for the CPU-bound task.
#
# c. Complete the implementation of the simulation by filling in the
#    run_threaded, run_parent, and run_child functions below.
#
# d. Run your simulations using 1-20 threads/processes and plot the running time.
#    Discuss your results: explain how and why they deviated from your
#    hypotheses, and explain why the curves have the shapes they do.
#

################################################################################
## sequential implementation ###################################################
################################################################################

def run_sequential(N):
    """perform N steps sequentially"""
    return do_steps(0,1,N)

################################################################################
## threaded implementation #####################################################
###############################################################################

class ThreadedWorker(Thread):
    def __init__(self,k,n,N):
        """initialize this thread to be the kth of n worker threads"""
        Thread.__init__(self)
        self.k      = k
        self.n      = n
        self.N      = N
        self.result = None

    def run(self):
        """execute the worker thread's work"""
        self.result = do_steps(self.k, self.n, self.N)

def run_threaded(num_threads, N):
    """use num_thread threads to perform N steps of work"""
    # TODO: create num_threads workers, run them, and
    # collect the results and return their sum.
    # Use the ThreadedWorker object directly above this function.
    # be sure that your implementation is concurrent!
    Thread_list = []
    for i in range(num_threads) :
        Thread = ThreadedWorker(i,num_threads,N)
        Thread.start()
        Thread_list.append(Thread)

    for thr in Thread_list:
        thr.join()
    sum = 0 
    for thr in Thread_list:
        sum += thr.result
    return sum

################################################################################
## multiprocess implementation #################################################
################################################################################

def run_parent(num_children, N):
    """use num_children subprocesses to perform N steps of work"""
    # TODO: fork num_children subprocesses to compute the results
    #
    # To launch a subprocess, you can invoke
    #  child = Popen(['program', 'arg1', 'arg2', 'arg3', ...])
    # this is equivalent to running
    #  $> program arg1 arg2 ... &
    # at the command line.
    #
    # To run another copy of the current python program, you can use
    # sys.executable to find the name of the python program, and sys.argv[0] to
    # find the name of the running script.  For example:
    #
    sum = 0
    children ='child'
    args = parse_args()
    child_list = []     
    for i in range(num_children):
        child = Popen([sys.executable, sys.argv[0], args.task_type, "child", str(args.num_processes), str(i)])
        child_list.append(child)

    for chld in child_list:   
        sum += chld.wait()
    #
    # To wait for a subprocess to complete, you can call child.wait(), which will
    # return the exit code of the child process.
    return sum

def run_child(N, args):
    """do the work of a single subprocess using do_steps"""
    # TODO: do the work for the ith (of n) children
    #
    # Note: if you run "python q03-timing.py child arg1 arg2 ...", this function
    # will be called with args equal to ['arg1', 'arg2', ...].
    #
    # the exit code of the process will be whatever is returned from this function
    process_num = args[1]
    process_max = args[0] 
	# print process_num
    # print process_max
    return do_steps(int(process_num),int(process_max),N)

################################################################################
## unit of work ################################################################
################################################################################

def do_step_cpu(i):
    """simulates a task that requires some processing"""
    total_val = 0
    random.seed(i)
    for j in range(10000):
        total_val += random.gauss(0,2)
    if total_val / float(10000) > 0:
        return 1
    else:
        return 0

def do_step_io(i):
    """simulates a task that requires a bit of processing and some I/O"""
    time.sleep(0.01)
    random.seed(i)
    val = random.gauss(0,2)
    if (val > 1):
        return 1
    else:
        return 0

# do_step will be set to either do_step_cpu or do_step_io
do_step = None

def do_steps(k, n, N):
    """given N units of work divided into n batches, performs the kth batch (k is
     in the range [kN/n,(k+1)N/n)."""
    start  = k * N/n
    finish = min((k+1) * N/n, N)
    value = 0
    for i in range(start,finish):
        value += do_step(i)
    return value

################################################################################
## program main function #######################################################
################################################################################

# Argument parsing
def parse_args():
    parser = argparse.ArgumentParser(description="Simulates a number of CPU or IO bound tasks.")
    parser.add_argument('task_type', help="The type of task to run.",
                        type=str, choices=["cpu", "io"])
    subparsers    = parser.add_subparsers(dest='command', help="How to run the tasks.")

    seq_parser    = subparsers.add_parser("sequential")

    thread_parser = subparsers.add_parser("threaded")
    thread_parser.add_argument('num_threads', help="Number of threads to run.", type=int)

    fork_parser   = subparsers.add_parser("forked")
    fork_parser.add_argument('num_processes', help="Number of processes to run.", type=int)

    child_parser  = subparsers.add_parser("child")
    child_parser.add_argument('other', help="Your arguments go here.", nargs='*')

    args = parser.parse_args()
    return args

if __name__ == '__main__':
    """parse the command line, execute the program, and print out elapsed time"""
    N = 100
    args = parse_args()

    if args.task_type == "cpu":
        do_step = do_step_cpu
    elif args.task_type == "io":
        do_step = do_step_io
    else:
        sys.exit(1)

    command = args.command
    start_time = time.time()

    if command == "sequential":
        print run_sequential(N)
    elif command == "threaded":
        print run_threaded(args.num_threads, N)
    elif command == "forked":
        print run_parent(args.num_processes, N)
    elif command == "child":
        # Note: this is an abuse of the exit status indication
        sys.exit(run_child(N, args.other))
    else:
        sys.exit(1)

    print "elapsed time: ", time.time() - start_time


##
## vim: ts=4 sw=4 et ai
##
