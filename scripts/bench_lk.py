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
    'cl_sung@cloudioh.com': {
        'id': 'R1uq7BgE8b',
        'oauth_token': '41b53348-154b-4242-9289-6ad080555724',
        'oauth_token_secret': '586dad3a-e7d9-45f2-b3d5-7e49ea2f3980'
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
