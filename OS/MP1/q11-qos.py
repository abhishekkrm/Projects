from threading import Thread, Lock, Condition
from time import sleep

# A service provider is providing computational resources to several competing
# businesses.  In order to provide fairness, the service provider has entered
# into a complicated series of contracts with its clients regarding which client
# jobs may be admitted.
#
# The rules are thus:
#
#   (a) there are no more than N jobs running
#   (b) govcom jobs are always allowed to run (subject to condition a)
#   (c) searchco jobs may not start if they would cause more than 80% of the
#       running jobs to be searchco jobs
#   (d) mysocialnetwork1 jobs may not start if there are any mysocialnetwork2
#       jobs running;
#   (e) nor may mysocialnetwork2 jobs start if there are mysocialnetwork1 jobs
#       (the two social networks hate each other so much they refuse to share
#       the same machine at the same time)
#
# The contracts make no guarantees about starvation.

# Implement the service provider's monitor using python Locks and
# Condition variables

class Provider(object):
    def __init__(self, n):
        # Lock for service provider
        self.service_provider = Lock()
        # Selectivily Notify each Serive
        # Service Govcom
        self.svc_govco = Condition(self.service_provider)
        # Service SearchCo
        self.svc_searchco = Condition(self.service_provider)
        # Service My Social Networking
        self.svc_mysocialnetwork = Condition(self.service_provider)
        # Max Job running 
        self.max_job = n
        # Current Jobs running 
        self.cur_job = 0
        # Current  SearchCo Jobs running
        self.searchco_job = 0
        # Indicates whether my socialnetwork is running  or not
        # O indicates not running.
        self.mysocialnetwork_running = 0
        pass

    def govco_enter(self):
        with self.service_provider:
            # No Space to schedule a job
            while self.cur_job > self.max_job - 1:
                self.svc_govco.wait()
            self.cur_job = self.cur_job + 1
        pass
    # End of govco_enter

    def govco_leave(self):
        with self.service_provider:
            self.cur_job = self.cur_job - 1
            # Selectively notify Govco if Job can be schedule
            if self.cur_job + 1 == self.max_job:
                self.svc_govco.notify()
            # Selectively notify MySocialNetwork if Job can be schedule
            if self.mysocialnetwork_running == 0:
                self.svc_mysocialnetwork.notify()
            # Selectively notify SearchCo if less than 80 % SearchCo job
            # and job can be schedule.
            if self.searchco_job < .8*self.cur_job - 1:
                self.svc_searchco.notify()
    # End of govco_leave


    def searchco_enter(self):
        with self.service_provider:
            while  self.cur_job > self.max_job - 1 or\
                   self.searchco_job > .8*self.cur_job - 1:
               self.svc_searchco.wait()
            self.cur_job = self.cur_job + 1
            self.searchco_job = self.searchco_job + 1
    # End of searchco_enter

    def searchco_leave(self):
        with self.service_provider:
            self.cur_job = self.cur_job - 1
            self.searchco_job = self.searchco_job - 1
            # Selectively notify Govco if Job can be schedule
            if self.cur_job + 1 == self.max_job:
                self.svc_govco.notify()
            # Selectively notify MySocialNetwork if Job can be schedule
            if self.mysocialnetwork_running == 0:
                self.svc_mysocialnetwork.notify()
            # Selectively notify SearchCo if less than 80 % SearchCo job
            # and job can be schedule.
            if self.searchco_job < .8*self.cur_job - 1:
                self.svc_searchco.notify()
    # End of searchco_leave

    def mysocial1_enter(self):
        with self.service_provider:
            while self.cur_job > self.max_job - 1 or\
                self.mysocialnetwork_running == 1:
                self.svc_mysocialnetwork.wait()
            self.mysocialnetwork_running = 1
            self.cur_job = self.cur_job + 1
    # End of mysocial1_enter

    def mysocial1_leave(self):
        with self.service_provider:
            self.mysocialnetwork_running = 0
            self.cur_job = self.cur_job - 1
            # No need to put any condition 
            self.svc_mysocialnetwork.notify()
            # Selectively notify Govco if Job can be schedule
            if self.cur_job + 1 == self.max_job:
                self.svc_govco.notify()
            # Selectively notify SearchCo if less than 80 % SearchCo job
            # and job can be schedule.
            if self.searchco_job < .8*self.cur_job - 1:
                self.svc_searchco.notify()
    # End of mysocial1_leave

    def mysocial2_enter(self):
        with self.service_provider:
            while self.cur_job > self.max_job - 1 or\
                self.mysocialnetwork_running == 1:
                self.svc_mysocialnetwork.wait()
            self.mysocialnetwork_running = 1
            self.cur_job = self.cur_job + 1
    # End of mysocial2_enter

    def mysocial2_leave(self):
        with self.service_provider:
            self.mysocialnetwork_running = 0
            self.cur_job = self.cur_job - 1
            # No need to put any condition 
            self.svc_mysocialnetwork.notify()
            # Selectively notify Govco if Job can be schedule
            if self.cur_job + 1 == self.max_job:
                self.svc_govco.notify()
            # Selectively notify SearchCo if less than 80 % SearchCo job
            # and job can be schedule.
            if self.searchco_job < .8*self.cur_job - 1:
                self.svc_searchco.notify()
    # End of mysocial2_leave


GOVCO    = 0
SEARCHCO = 1
MYSOC1   = 2
MYSOC2   = 3

class Job(Thread):
    def __init__(self, job_type, provider):
        Thread.__init__(self)
        self.job_type = job_type
        self.provider = provider

    def run(self):
        enters = [self.provider.govco_enter,
                  self.provider.searchco_enter,
                  self.provider.mysocial1_enter,
                  self.provider.mysocial2_enter]
        leaves = [self.provider.govco_leave,
                  self.provider.searchco_leave,
                  self.provider.mysocial1_leave,
                  self.provider.mysocial2_leave]
        names  = ['govco', 'searchco', 'mysocial1', 'mysocial2']

        print("%s job trying to enter" % names[self.job_type])
        enters[self.job_type]()
        print("%s job admitted" % names[self.job_type])
        sleep(0.1)
        print("%s job leaving" % names[self.job_type])
        leaves[self.job_type]()
        print("%s job done" % names[self.job_type])

max_jobs = 15
numbers = [10, 35, 2, 4]
provider = Provider(max_jobs)
for co in [GOVCO, SEARCHCO, MYSOC1, MYSOC2]:
    for i in range(numbers[co]):
        Job(co, provider).start()

##
## vim: ts=4 sw=4 et ai
##
