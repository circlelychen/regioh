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
        import logging
        import logging.config
        try:
            logging.config.fileConfig('logger.conf')
            app._logger = logging.getLogger(__name__)
            app.logger.info("Production mode")
        except:
            app.logger.debug("Replace logger error")
    else:
        app.logger.debug("Debug mode")

setup_logging()

import regioh.api_view
import regioh.views
