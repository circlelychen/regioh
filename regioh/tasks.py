
import tempfile
import json
import os

from regioh.celery import celery

from regioh import app
from gdapi.gdapi import GDAPI
import api_helper


@celery.task(ignore_result=True)
def update_contact_file(id, reg_item, profile, contact,
                        worker_name='cipherbox@cloudioh.com.cred.json'):
    from default_config import PROJECT_ROOT

    partner_contact_file_id = contact.get('contact_fid', None)
    if partner_contact_file_id is None:
        return False

    try:
        ga = GDAPI(os.path.join(os.path.dirname(PROJECT_ROOT), 'accounts', worker_name))
        _, temp_path = tempfile.mkstemp()
        success = ga.download_file(partner_contact_file_id, temp_path)

        app.logger.debug("{0} download {1}'s [{2}] to {3}"
                        "".format(worker_name, contact.get('email', None),
                                  partner_contact_file_id, temp_path))
    except Exception as e:
        app.logger.error("[FAIL] {0} download {1}, "
                         "exception: {2}".format(worker_name,
                                                 contact.get('email',
                                                             None),
                                                 repr(e)))
        #[need to implement] how to handle error
        return False


    with open(temp_path, "rb") as fin:
        try:
            jobj = json.load(fin)
        except Exception as e:
            app.logger.error("[FAIL] {0} json.dump(contact_file) {1}, "
                            "exception: {2}".format(worker_name,
                                                    contact.get('email',
                                                                None),
                                                    repr(e)))
            #[need to implement] how to handle error
            return False

    if not jobj or not jobj['contacts']:
        #json format error
        #[need to implement] how to handle error
        return False

    #update contacts content
    jobj['contacts'][id] = reg_item
    for index in profile:
        jobj['contacts'][id][index] = profile[index]
    api_helper._write_contacts_result(temp_path, code=0, contacts=jobj['contacts'])

    try:
        result = ga.update_file(partner_contact_file_id, temp_path)
        app.logger.debug("{0} upload {1}'s [{2}]"
                        "".format(worker_name, contact.get('email', None),
                                partner_contact_file_id))
    except Exception as e:
        app.logger.error("[FAIL] {0} update {1}, "
                            "exception: {2}, gdapi.update_file "
                            "response: {3}".format(workder_name,
                                                contact.get('email', None),
                                                repr(e),
                                                result))
        app.logger.error(result)

    success = ga.unshare(partner_contact_file_id, contact['permid'])
    ga.make_user_reader_for_file(partner_contact_file_id,
                                    contact.get('email', None))
    os.unlink(temp_path)

