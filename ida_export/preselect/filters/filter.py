class FunctionFilter:
    """
    This abstract base class defines the filter interface.
    """

    def __init__(self, debug=False):
        self.debug = debug

    def decide(self, func_addr):
        """
        Decides whether or not a function is a proper candidate.
        The actual logic is implemented in each subclass.
        """
        pass

    def log(self, msg):
        if self.debug:
            print('[*] [{}] {}'.format(self.__class__.__name__, msg))
