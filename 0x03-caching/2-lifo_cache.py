#!/usr/bin/python3
"""
FIFO caching
"""


BaseCaching = __import__('base_caching').BaseCaching


class LIFOCache(BaseCaching):
    """
    LIFOCache
    """
    def __init__(self):
        """
        overload
        """
        super().__init__()

    def put(self, key, item):
        """
        assign to the dictionary
        """
        if key and item:
            self.cache_data[key] = item
        if len(self.cache_data) > BaseCaching.MAX_ITEMS:
            self.cache_data.pop(self.remove)
            print("DISCARD: {}".format(self.remove, end=""))
        if key:
            self.remove = key
        else:
            pass

    def get(self, key):
        """
        get value of key from dict
        """
        if key is None:
            return None
        return self.cache_data.get(key)
