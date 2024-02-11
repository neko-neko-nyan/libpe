

class PEFormatException(Exception):
    def __init__(self, fp, offset, message):
        self.fp = fp
        self.address = fp.pos + offset
        self.message = message
