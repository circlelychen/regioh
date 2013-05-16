
#!/usr/bin/env python
import os
import sys
import logging
import threading

path = os.getcwd()
if path not in sys.path:
    sys.path.append(path)

from gdapi.gdapi import GDAPI
import tempfile
import json
import time

def create_folder_upload_file(parent_id, file_path):

    #random string as folder name
    from regioh.api_helper import generate_security_code
    security_code_as_folder_name = generate_security_code()

    # insert "contacts file" into GD
    from regioh.default_config import GD_CRED_FILE
    ga = GDAPI(GD_CRED_FILE)
    folder_id = ga.create_folder(parent_id,
                                 security_code_as_folder_name)
    result = ga.create_or_update_file(folder_id,
                                      file_path,
                                      'Cipherbox Contacts')

def main(argv):
    if len(argv) < 2:
        sys.exit("Usage: {0} <num_thread> <file_path>".format(argv[0]))
    num_thread = argv[1]
    file_path = argv[2]
    if not os.path.isfile(file_path):
        sys.exit("File is not exist")

    logger = logging.getLogger('gdapi')
    #logger.addHandler(logging.StreamHandler())
    logger.addHandler(logging.NullHandler())
    logger.setLevel(logging.DEBUG)

    # insert "contacts file" into GD
    from regioh.default_config import GD_CRED_FILE
    ga = GDAPI(GD_CRED_FILE)
    root_id = ga.create_folder('root',
                               'gd_post_root')
    start = time.time()
    try:
        for i in range(int(num_thread)):
            t = threading.Thread(target=create_folder_upload_file,
                                args=(root_id,file_path,),
                                name='create_folder_upload_file')
            t.setDaemon(True)
            t.start()

        print "===== upload {0} with {1} threading =====".format(file_path,
                                                                num_thread)
        start = time.time()
        print "start at {0}".format(start)
        for thread in threading.enumerate():
            if thread is not threading.currentThread():
                thread.join()
        end = time.time()
        print "end at {0}".format(end)
        print "time elapsed: < {0} > sec".format(end - start)
    except Exception as e:
        print repr(e)
        raise

if __name__ == '__main__':
    main(sys.argv)
