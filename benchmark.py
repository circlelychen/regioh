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

from regioh.default_config import PROJECT_ROOT
from regioh import api_helper

path = os.getcwd()
if path not in sys.path:
    sys.path.append(path)

from gdapi.gdapi import GDAPI
q = Queue()

accounts = ['cipherbox@cloudioh.com.cred.json',
            'developer@cloudioh.com.cred.json',
            'apple110531@gmail.com.cred.json',
            'banana110531@gmail.com.cred.json',
            'cherry110531@gmail.com.cred.json',
            'justin_jan@cloudioh.com.cred.json',
            'jjcipher@gmail.com.cred.json',
            'howard_chen@cloudioh.com.cred.json'
           ]
#the following content depicts 100 connections for a person
contact_file = 'connection_contacts'
CONNECT_NUM = 0

randstr = lambda x: u''.join(
    random.choice(string.ascii_lowercase + string.digits) for x in xrange(x))

local_data = threading.local()

def worker(folder_id, queue, ga, contacts):
    while True:
        signal = queue.get()

        # 1. insert "contacts file" into GD
        #folder_id = api_helper.create_folder(folder_id,
        #                          ''.join([threading.currentThread().getName(),'-',
        #                                   str(signal)
        #                                  ])
        #                         )

        # 2. insert "contacts file" into GD
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

        #for i in xrange(CONNECT_NUM):
        #    # 3. download file
        #    _, temp_path = tempfile.mkstemp()
        #    if api_helper.download_file(file_id, temp_path):
        #        with open(temp_path, "wb") as fout:
        #            json.dump(contacts, fout, indent=2)
        #        # 4. update file
        #        api_helper.update_file(file_id, temp_path)


        #ga.create_file(folder_id, temp_path,
        #            ''.join([threading.currentThread().getName(),
        #                    '-', str(signal)]))
        queue.task_done()

def main(argv):
    logger = logging.getLogger('gdapi')
    logger.addHandler(logging.StreamHandler())
    logger.setLevel(logging.DEBUG)

    # master accoutn create 'testreg' and share with other 'slaves'
    #ga = GDAPI(os.path.join(os.path.dirname(PROJECT_ROOT), 'accounts',
    #                        accounts[0]))
    #folder_id = ga.create_folder(u'root', 'testreq')
    with open(os.path.join(os.path.dirname(PROJECT_ROOT),
                           'accounts',
                           contact_file),
              'rb') as f:
        contacts = json.load(f,)
        print contacts


    for account in accounts:
        ga = GDAPI(os.path.join(os.path.dirname(PROJECT_ROOT), 'accounts', account))
        folder_id = ga.create_folder(u'root', 'testreq')
        t = threading.Thread(target=worker,
                             args=(folder_id, q, ga, contacts,))
        t.setDaemon(True)
        t.start()

    from timeit import default_timer as timer
    start = timer()
    for x in xrange(1):
        q.put(x)
    q.join()
    logger.info('Total: %r sec', timer() - start)

if __name__ == '__main__':
    main(sys.argv)
