from functools import wraps
from regioh.exceptions import abort
from flask import request
from flask import g, session
from regioh import app

def extract_request_data(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if request.form:
            user_email = request.form.get('email', None)
            pubkey = request.form.get('pubkey', None)
            pub_key_md5 = request.form.get('pubkey_md5', 'N/A')
            permid = request.form.get('permid', 'N/A')
            linked_data = request.form.get('linkedin_data', None)
            token = request.form.get('token', None)
            linkedin_id = request.form.get('linkedin_id', None)
            security_code = request.form.get('identity_code', None)
            nonce = request.form.get('nonce', None)
        else:
            try:
                jreq = json.loads(request.data)
            except Exception as e:
                app.logger.error("[FAIL] exception: {0} \n {1}".format(repr(e),
                                                                      request.data))
                abort(400, {'message': 'incorrect POST data: {0}'.format(request.data)})
            user_email = jreq.get('email', None)
            pub_key_md5 = jreq.get('pubkey_md5', '')
            permid = jreq.get('permid', '')
            pubkey = jreq.get('pubkey', None)
            linked_data = jreq.get('linkedin_data', {})
            token = jreq.get('token', None)
            linkedin_id = jreq.get('linkedin_id', None)
            security_code = jreq.get('identity_code', None)
            nonce = jreq.get('nonce', None)
        session['user_email'] = user_email
        session['pubkey'] = pubkey
        session['linked_data'] = linked_data
        session['token'] = token
        session['pub_key_md5'] = pub_key_md5
        session['permid'] = permid
        session['linkedin_id'] = linkedin_id
        session['security_code'] = security_code
        session['nonce'] = nonce
        return f(*args, **kwargs)

    return decorated_function


def _format_response(item):
    ''' (dict) -> dict

    return item deleting (oauth, token, reg_data)

    >> _format_response(item)
    {
        "status": <str>,
        "linkedin_id": <str>
    }
    '''
    del item['oauth_token']
    del item['oauth_token_secret']
    del item['token']
    del item['reg_data']
    return item
