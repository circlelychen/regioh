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
from gdapi.gdapi import GDAPI
q = Queue()

###########################################################
# the following content depicts 100 connections for a person
###########################################################
master = 'cipherbox@cloudioh.com.cred.json'
accounts = ['cipherbox@cloudioh.com.cred.json',
            'developer@cloudioh.com.cred.json',
            'apple110531@gmail.com.cred.json',
            'banana110531@gmail.com.cred.json',
            'cherry110531@gmail.com.cred.json',
            'justin_jan@cloudioh.com.cred.json',
            'jjcipher@gmail.com.cred.json',
            'howard_chen@cloudioh.com.cred.json'
           ]

contact_file = 'connection_contacts'
CONNECT_NUM = 0
###########################################################
# the following content depicts 100 connections for a person
###########################################################

def worker(folder_id, queue, ga, contacts):
    while True:
        signal = queue.get()


        # 1. insert "contacts file" into GD
        _, temp_path = tempfile.mkstemp()
        with open(temp_path, "wb") as fout:
            json.dump(contacts, fout, indent=2)
        file_id = ga.create_or_update_file(folder_id,
                                           os.path.join(os.path.dirname(PROJECT_ROOT),
                                                        'accounts',
                                                        contact_file),
                                           ''.join([threading.currentThread().getName(),
                                                    '-', str(signal)
                                                   ])
                                          )
        os.unlink(temp_path)

        queue.task_done()

def main(argv):
    if len(argv) < 2:
        sys.exit("Usage: {0} <num_job> ".format(argv[0]))

    logger = logging.getLogger('gdapi')
    logger.addHandler(logging.StreamHandler())
    logger.setLevel(logging.DEBUG)

    #  load contacts content for running benchmark
    with open(os.path.join(os.path.dirname(PROJECT_ROOT),
                           'accounts',
                           contact_file),
              'rb') as f:
        contacts = json.load(f)

    # master create shared folder
    master_ga = GDAPI(os.path.join(os.path.dirname(PROJECT_ROOT),
                                   'accounts',
                                   master))
    root_id = master_ga.create_folder(u'root', os.path.basename(__file__))

    # initial worker threads for each account
    for account in accounts:
        tokens = account.split('.')
        perm_id = master_ga.make_user_writer_for_file(root_id,
                                                      ".".join([tokens[0], tokens[1]]))
        ga = GDAPI(os.path.join(os.path.dirname(PROJECT_ROOT),
                                'accounts',
                                account))
        t = threading.Thread(target=worker,
                             args=(root_id, q, ga, contacts,))
        t.setDaemon(True)
        t.start()

    # dispatch jobs into Queue
    from timeit import default_timer as timer
    start = timer()
    for x in xrange(int(argv[1])):
        q.put(x)
    q.join()
    logger.info('Total: %r sec', timer() - start)

if __name__ == '__main__':
    main(sys.argv)
