
import tempfile
import json
import os

from regioh.celery import celery

from regioh import app
import api_helper
import threading
from Queue import Queue

queue = Queue()

def worker(folder_id, queue, ga, contacts):
    app.logger.info('Thread {0} starts ...'.format(threading.currentThread().getName()))
    while True:
        signal = queue.get(block=True)
        app.logger.info('Thread {0} process ...'.format(threading.currentThread().getName()))
        queue.task_done()

    app.logger.info('Thread {0} ends ...'.format(threading.currentThread().getName()))


def update_contact_file(id, reg_item, profile, contact):
    partner_contact_file_id = contact.get('contact_fid', None)
    if partner_contact_file_id:
        app.logger.debug("fetch partner {0}'s contact file with ID:{1}"
                         "".format(contact.get('email', None), partner_contact_file_id))
        _, temp_path = tempfile.mkstemp()
        if api_helper.download_file(partner_contact_file_id, temp_path):
            #download partners' "contacts file"
            app.logger.debug("download contact file with ID:{0} "
                                "and store as {1}".format(partner_contact_file_id,
                                                        temp_path))
            with open(temp_path, "rb") as fin:
                jobj = json.load(fin)
            if jobj and id in jobj['contacts']:
                app.logger.debug("load contact file from {0} ".format(temp_path) )
                jobj['contacts'][id] = reg_item
                for index in profile:
                    jobj['contacts'][id][index] = profile[index]
                with open(temp_path, "wb") as fout:
                    api_helper._write_contacts_result(fout, code=0, contacts=jobj['contacts'])
                app.logger.debug("update contact file {0} for {1}"
                                 "".format(temp_path,
                                           contact.get('email', None))
                                )
                api_helper.update_file(partner_contact_file_id, temp_path)
                success = api_helper.unshare(partner_contact_file_id)
                partner_perm_id = api_helper.make_user_reader_for_file(partner_contact_file_id,
                                                                       contact.get('email',
                                                                                   None)
                                                                      )
                os.unlink(temp_path)


@celery.task(ignore_result=True)
def update_connection_contacts_files(id, reg_item, profile, contacts):
    # for each partner in 'contacts file', update their' "contact files"
    for key in contacts:
        if key == 'me':
            continue

        t = threading.Thread(target=update_contact_file,
                            args=(id,reg_item,profile,contacts[key],),
                            name='update_connection_contacts_files')
        t.setDaemon(True)
        t.start()
