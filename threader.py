#I want to create a scritp that would help get return values from threaded function

#Useful libraries that I would be working with
from threading import Thread
import queue

#Declaring the class
class thread_(object):
    def __init__(self, target=None, args=(), **kwargs):
        self._que = queue.Queue()
        self._t = Thread(target=lambda q,arg1,kwargs1: q.put(target(*arg1, **kwargs1)) ,
                args=(self._que, args, kwargs), )
        self._t.start()

    def join(self):
        self._t.join()
        return self._que.get()

