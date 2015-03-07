# See shallowsky.com/blog/programming/python-tee.html
#
# This is even simpler.

import sys

class Tee:

    def __init__(self, filename, mode):
        self.open(filename, mode)

    def __del__(self) :
        self.file.close()

    def open(self, filename, mode):
        self.close()
        self.file = open(filename, mode)

    def close(self):
        if self.file:
            self.file.close()
        self.file = None

    def write(self, text):
        sys.stdout.write(text)
        if self.file:
        self.file.write(text)

    def flush(self):
        sys.stdout.flush()
        if self.file:
            self.file.flush()

