#!/usr/bin/env python
import os
import sys
import logging
import tempfile
import string
import random
import threading
import json
from Queue import Queue

path = os.getcwd()
if path not in sys.path:
    sys.path.append(path)

from regioh.default_config import PROJECT_ROOT
from regioh.api_helper import get_linkedin_connection
q = Queue()

accounts = {
    'truecirclely@gmail.com': {
        'id': 'rdlsVH788A',
        'oauth_token': 'e64bac71-cb18-4865-bfdd-554f7426eb46',
        'oauth_token_secret': '3dc5ffab-9729-4478-983a-f2b95f1a8ce8'
    },
    'apple110531@gmail.com': {
        'id': 'AryLrgEqrF',
        'oauth_token': 'dedfb682-f57a-4d66-9e10-6ef6c7d72bb5',
        'oauth_token_secret': '8644996e-e534-412b-bcd2-463a1ad5d2d2'
    },
    'banana110531@gmail.com': {
        'id': 'tmoijVoPVd',
        'oauth_token': '6ba8a7ac-bf3d-495d-8f1f-6a0d7994074d',
        'oauth_token_secret': '1d1e2754-0d24-4cf4-bd70-f364f55c4ac4'
    }
}



def worker(queue, account):
    while True:
        signal = queue.get()

        status, jobj = get_linkedin_connection(
            account['oauth_token'],
            account['oauth_token_secret'])
        if status != 200:
            logger = logging.getLogger('gdapi')
            logger.debug(status)
            logger.debug(jobj)
        queue.task_done()

def main(argv):
    if len(argv) < 2:
        sys.exit("Usage: {0} <num_job> ".format(argv[0]))

    logger = logging.getLogger('gdapi')
    logger.addHandler(logging.StreamHandler())
    logger.setLevel(logging.DEBUG)

    for key in accounts:
        t = threading.Thread(target=worker,
                             args=(q,accounts[key]))
        t.setDaemon(True)
        t.start()

    from timeit import default_timer as timer
    start = timer()
    for x in xrange(int(argv[1])):
        q.put(x)
    q.join()
    logger.info('Total: %r sec', timer() - start)

if __name__ == '__main__':
    main(sys.argv)
