class PostProcessor:
    def __init__(self, debug=False):
        self.debug = debug

    def process(self, func_addr, filter_name):
        """
        Returns an array of function addresses to include.
        """
        pass
    
    def log(self, msg):
        if self.debug:
            print('[*] [{}] {}'.format(self.__class__.__name__, msg))
