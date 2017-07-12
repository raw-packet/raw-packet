from Queue import Queue
from threading import Thread


class ThreadManager(object):
    def _worker(self):
        while True:
            try:
                func, args, kwargs = self._threads.get()
                func(*args, **kwargs)
            except Exception, e:
                print e
            self._threads.task_done()

    def __init__(self, thread_count):
        self._thread_count = thread_count
        self._threads = Queue(maxsize=self._thread_count)
        for i in range(self._thread_count):
            worker_thread = Thread(target=self._worker)
            worker_thread.setDaemon(True)
            worker_thread.start()

    def add_task(self, func, *args, **kwargs):
        self._threads.put((func, args, kwargs,))

    def wait_for_completion(self):
        self._threads.join()
