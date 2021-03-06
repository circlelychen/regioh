from flask import Flask
import threading
import os

app = Flask(__name__)
app.config.from_object('regioh.default_config')
app.config.from_envvar('FLASKR_SETTINGS', silent=True)
app.secret_key = '\xe1\r#\x99\xfb\x10T\x11\x07\x8a+\x00\xbe\xe7$\xa1\x86\x05\x97\xf0\xe0\xa7\xd9\xed'

import regioh.v2.api_view
import regioh.views

#@app.before_first_request
def setup_logging():
    if not app.debug and not app.config['TESTING']:
        # In production mode, add log handler to sys.stderr.
        try:
            #SES Handler
            from SESHandler import SESHandler
            import logging
            from default_config import AWS_ACCESS_KEY
            from default_config import AWS_SECRET_ACCESS_KEY
            from default_config import AWS_SES_SENDER
            formatter = logging.Formatter('''
                Message type:       %(levelname)s
                Location:           %(pathname)s:%(lineno)d
                Module:             %(module)s
                Function:           %(funcName)s
                Time:               %(asctime)s

                Messageu

                %(message)s
                            ''')
            handler = SESHandler(AWS_ACCESS_KEY, AWS_SECRET_ACCESS_KEY, AWS_SES_SENDER,
                                'howard_chen@cloudioh.com', '[REGSVR] REGIOH Failed')
            handler.setFormatter(formatter)
            handler.setLevel(logging.ERROR)
            app.logger.addHandler(handler)

            #Console Handler
            handler = logging.StreamHandler()
            formatter = logging.Formatter('%(asctime)s %(levelname)s: '
                                          '%(message)s '
                                          '[in %(module)s :%(lineno)d]')
            handler.setFormatter(formatter)
            handler.setLevel(logging.DEBUG)
            app.logger.addHandler(handler)

            # set level of app.logger
            app.logger.setLevel(logging.DEBUG)
            app.logger.info("Production mode")
        except:
            app.logger.debug("Replace logger error")
    else:
        app.logger.debug("Debug mode")

def setup_shared_folder():
    if not app.debug and not app.config['TESTING']:
        from gdapi.gdapi import GDAPI
        from default_config import MASTER
        from default_config import ACCOUNTS
        from default_config import PROJECT_ROOT
        # master create shared folder
        master_ga = GDAPI(os.path.join(os.path.dirname(PROJECT_ROOT),
                                        'accounts',
                                        MASTER))
        result = master_ga.query_title(os.path.basename(__name__))
        if len(result) == 1 and result[0]['id']:
            app.config['gd_shared_roo_id'] = result[0]['id']
            return True

        #gd_shared_root_id does not exist, create folder and share to each
        #worker
        root_id = master_ga.create_folder(u'root', os.path.basename(__name__))
        success = master_ga.unshare(root_id)
        app.config['gd_shared_roo_id'] = root_id
        # initial worker threads for each account
        for account in ACCOUNTS:
            tokens = account.split('.')
            perm_id = master_ga.make_user_writer_for_file(root_id,
                                                          ".".join([tokens[0], tokens[1]]))
setup_logging()
setup_shared_folder()
