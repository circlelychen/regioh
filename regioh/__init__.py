from flask import Flask
import os

app = Flask(__name__)
app.config.from_object('regioh.default_config')
app.config.from_envvar('FLASKR_SETTINGS', silent=True)

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
