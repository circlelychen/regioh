from flask import Flask
import os

app = Flask(__name__)
app.config.from_object('regioh.default_config')
app.config.from_envvar('FLASKR_SETTINGS', silent=True)
app.secret_key = '\xe1\r#\x99\xfb\x10T\x11\x07\x8a+\x00\xbe\xe7$\xa1\x86\x05\x97\xf0\xe0\xa7\xd9\xed'

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
                                'cipherbox@cloudioh.com', '[REGSVR] REGIOH Failed')
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

setup_logging()

import regioh.api_view
import regioh.views

