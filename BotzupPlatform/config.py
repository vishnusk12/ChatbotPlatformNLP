'''
Created on 31-Jul-2018

@author: Vishnu
'''

from .models import RequestCache

def create_cache(CACHE_ID):
    try:
        req_cache = RequestCache.objects.get(cache_id=CACHE_ID)
    except RequestCache.DoesNotExist:
        req_cache = None
    return req_cache
