
import logging
import os
import sys
import requests
import json
import urlparse

REG_API_URL = 'https://54.248.221.46'

path = os.getcwd()
if path not in sys.path:
    sys.path.append(path)


def replicate(argv):
    from regioh.api_helper import get_dynamodb_table
    from boto.dynamodb.condition import EQ
    tbl = get_dynamodb_table('v2_auth')
    actives = tbl.scan(scan_filter = {
        "status": EQ('active')
    })#, attributes_to_get = ['linkedin_id', 'status'])

    result = {}
    for active in actives:
        if active.get('contact_fid_new_new', None):
            print '{0} with fid:{1}'.format(active['linkedin_id'],
                                            active.get('contact_fid_new_new', None))
            active['LinkedIn_Contacts_FID']=active.get('contact_fid_new_new', None)
            active.put()


def write_result(out_file, code, result):
    j = { 'code': code, 'result': result }
    with open(out_file, 'wb') as fo:
        json.dump(j, fo, indent=2)

def v2_register_email(email, pubkey, identity_code):
    """Return C"""
    url = urlparse.urljoin(REG_API_URL, '/v2/register')
    resp = requests.post(url,
                         headers={
                             'content-type': 'application/json'
                         },
                         data=json.dumps({
                             'email': email,
                             'pubkey': pubkey,
                             'identity_code': identity_code
                         }), verify=False)
    return resp.status_code, resp.json()

def v2_register(argv):
    if len(argv) < 2:
        sys.exit("Usage: {0} v2_register <{1}> <{2}>".format(
            sys.argv[0], 'input_file', 'output_file'))
    with open(argv[0], 'rb') as fin:
        jobj = json.load(fin)
    identity_code = jobj['identity_code']
    email = jobj['email']
    pubkey = jobj['pubkey']
    out_file = argv[1]
    status, jobj = v2_register_email(email, pubkey, identity_code)
    if status != 200:
        write_result(out_file, -1, jobj)
        return -1
    write_result(out_file, jobj.get('code', -1), jobj.get('status', 'error'))
    return 0

def doCommand(cmd, *args):
    if cmd in globals():
        return globals()[cmd](list(args))
    else:
        raise LookupError("Command not recognised")

def main(argv):
    try:
        doCommand(argv[1], *argv[2:])
    except Exception as e:
        import logging
        logging.basicConfig()
        logging.getLogger().exception(e)

if __name__ == '__main__':
    sys.exit(main(sys.argv))

