
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
    ga = GDAPI(os.path.join(os.path.dirname(PROJECT_ROOT),
                            'accounts',
                            worker_name))
    app.logger.debug("{0} start to update partner {1}'s contact file with ID:{1}"
                     "".format(worker_name, contact.get('email', None)))
    try:
        _, temp_path = tempfile.mkstemp()
        success = ga.download_file(partner_contact_file_id, temp_path)
    except Exception as e:
        app.logger.error("[FAIL] {0} download {1}, "
                         "exception: {2}".format(worker_name,
                                                 contact.get('email',
                                                             None),
                                                 repr(e)))
        return False

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

        try:
            result = ga.update_file(partner_contact_file_id, temp_path)
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

