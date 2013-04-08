# -*- coding: utf-8 -*-
"""
"""
import os
from regioh import app
from flask import Flask, request, jsonify
from .exceptions import abort
from api_helper import query_dynamodb
from api_helper import addto_dynamodb
from api_helper import update_dynamodb
import json

def _extract_request_data(request):
    if request.form:
        user_email = request.form.get('email', None)
        pub_key = request.form.get('pubkey', None)
        token = request.form.get('token', None)
    else:
        try:
            jreq = json.loads(request.data)
        except:
            abort(400, {'message': 'incorrect POST data: {0}'.format(request.data)})
        user_email = jreq.get('email', None)
        pub_key = jreq.get('pubkey', None)
        token = jreq.get('token', None)
    if request.files and request.files.get('pubkey', None):
        fs_pubkey = request.files['pubkey']
        pub_key = fs_pubkey.read()
    return user_email, pub_key, token

@app.route('/v1/check', methods=['POST'])
def v1_check():
    """Verify if the (email, public key) is active/present"""
    user_email, pub_key, _ = _extract_request_data(request)
    if user_email is None or pub_key is None:
        abort(400, {'code': 400, 'message': 'missing email or public key'})
    status, record = query_dynamodb(user_email, pub_key)
    return jsonify(code=200, status=status)


@app.route('/v1/register', methods=['POST'])
def v1_register():
    from api_helper import generate_R
    from api_helper import compute_C
    from api_helper import notify_email
    from binascii import hexlify
    user_email, pub_key, _ = _extract_request_data(request)
    status, record = query_dynamodb(user_email, pub_key)
    if status == u'active':
        abort(403, {'code': 403, 'message': 'Invalid registration'})
    elif status == u'inactive':  # mean a pending activation is on the way
        abort(403, {'code': 403, 'message': 'Pending registration'})
    elif status == u'invalid':
        pass
    else:  # 'empty'
        pass
    R = generate_R()
    C = compute_C(pub_key, R)
    # store in dynamoDB
    addto_dynamodb(user_email, pub_key,
                   token=hexlify(R))
    # now email with C
    notify_email(user_email, C)
    if app.config['TESTING']:
        return jsonify(code=200, status='inactive', C=C, R=hexlify(R))
    else:
        return jsonify(code=200, status='inactive')


@app.route('/v1/resend', methods=['POST'])
def v1_resend():
    from api_helper import compute_C
    from api_helper import notify_email
    from binascii import unhexlify
    user_email, pub_key, _ = _extract_request_data(request)
    status, record = query_dynamodb(user_email, pub_key)
    if status != u'inactive':  # mean a pending activation is on the way
        abort(403, {'code': 403, 'message': 'Invalid registration'})
    print record['token']
    C = compute_C(pub_key, unhexlify(record['token']))
    # store in dynamoDB
    update_dynamodb(record)
    # now email with C
    notify_email(user_email, C)
    return jsonify(code=200, status='inactive')


@app.route('/v1/confirm', methods=['POST'])
def v1_confirm():
    from binascii import hexlify
    user_email, pub_key, token = _extract_request_data(request)
    status, record = query_dynamodb(user_email, token=hexlify(token))
    if status == u'active':
        abort(403, {'code': 403, 'message': 'Invalid confirmation'})
    elif status == u'invalid':
        abort(404, {'code': 404, 'message': 'No such record'})
    else:  # 'empty'
        pass
    record['status'] = u'active'
    update_dynamodb(record)
    return jsonify(code=200, status=record['status'])


if __name__ == '__main__':
    app.run(host='0.0.0.0')
