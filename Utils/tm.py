# region Description
"""
tm.py: Thread Manager class
Author: Evgeny @4ekin Bechkalo
License: MIT
Copyright 2019, Raw-packet Project
"""
# endregion

# region Import
from Queue import Queue
from threading import Thread
# endregion

# region Authorship information
__author__ = 'Evgeny @4ekin Bechkalo'
__copyright__ = 'Copyright 2019, Raw-packet Project'
__credits__ = ['']
__license__ = 'MIT'
__version__ = '0.0.4'
__maintainer__ = 'Vladimir Ivanov'
__email__ = 'ivanov.vladimir.mail@gmail.com'
__status__ = 'Production'
# endregion


# region Class ThreadManager
class ThreadManager(object):

    # Main background worker - wrapper of function
    def _worker(self):
        while True:
            try:
                # get one function with arguments from queue
                func, args, kwargs = self._threads.get()
                # and execute it
                func(*args, **kwargs)
            except Exception, e:
                print e
            self._threads.task_done()

    def __init__(self, thread_count):
        """
        Constructor for ThreadManager class
        :param thread_count: Maximal capacity of threads queue
        """
        self._thread_count = thread_count
        self._threads = Queue(maxsize=self._thread_count)
        for _ in range(self._thread_count):
            worker_thread = Thread(target=self._worker)
            worker_thread.setDaemon(True)
            worker_thread.start()

    def add_task(self, func, *args, **kwargs):
        """
        Add task to queue for background working
        :param func: Target function for executing
        :param args: Positional arguments of function
        :param kwargs: Keyword arguments of function
        :return: None
        """
        self._threads.put((func, args, kwargs,))

    def wait_for_completion(self):
        """
        Sync all threads
        :return: None
        """
        self._threads.join()
# endregion