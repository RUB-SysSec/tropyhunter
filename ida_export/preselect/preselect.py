import inspect

import filters
import post_processors


def get_filters():
    """
    Loads filters by inspecting members of the 'filters' package.
    """
    filter_classes = []
    for _, member in inspect.getmembers(filters):
        if inspect.isclass(member):
            filter_classes.append(member)

    return filter_classes

def get_post_processors():
    """
    Loads post processors by inspecting members of the 'post_processors' package.
    """
    post_processor_classes = []
    for _, member in inspect.getmembers(post_processors):
        if inspect.isclass(member):
            post_processor_classes.append(member)

    return post_processor_classes


class Preselector():
    def __init__(self, debug=False):
        self.debug = debug
        self.filters = list()
        self.post_processors = list()
        
        # Instantiate filters
        for filter_class in get_filters():
            self.filters.append(filter_class(debug=debug))

        # Instantiate post processors
        for post_processor_class in get_post_processors():
            self.post_processors.append(post_processor_class(debug=debug))

    def decide(self, func_addr):
        """
        Uses all filters to determine whether this is a candidate or not.
        """
        for filter_obj in self.filters:
            if filter_obj.decide(func_addr):
                filter_name = filter_obj.__class__.__name__
                self.log('0x{:x} detected by {}!'.format(func_addr, filter_name))
                return True, filter_name

        # No filter said this is a candidate
        return False, None

    def post_process(self, func_addr, filter_name):
        """
        Looks for more eligible functions based on a candidate.
        """
        additional_functions = set()

        for post_processor_obj in self.post_processors:
            for func in post_processor_obj.process(func_addr, filter_name):
                self.log('0x{:x} detected by {}!'.format(func, post_processor_obj.__class__.__name__))
                additional_functions.add(func)

        return list(additional_functions)
    
    def log(self, msg):
        """
        Logs the message if debugging is enabled.
        """
        if self.debug:
            print('[*] [{}] {}'.format(self.__class__.__name__, msg))
