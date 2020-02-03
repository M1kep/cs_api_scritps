	"""V1 Submits to ANY Class for first policy for a given CID,
	 will need to analyse how Policy works,
	  or change precedence to ensure works in all scenarions"""



from oauthlib.oauth2 import BackendApplicationClient
from requests.auth import HTTPBasicAuth
from requests_oauthlib import OAuth2Session
import json
from IPython.core.debugger import set_trace
import time
import logging 

expire = 0

 
client_id = 'c3f3a21b955149e29cac13218d160ca5'
client_secret = 'Mm3lv2f1Ce8HkUbENqW9JZSQhBua5i6V4DPs7rG0'
token_url = 'https://api.crowdstrike.com/oauth2/token'

extra = {
'client_id': client_id,
'client_secret': client_secret,
 }


token_saver = ''

def create_file_submission_json_sn(serial_number,combined_id):
    updateValues =    {
                                "class":"ANY",
                                "vendor_name": "",
                                "product_name": "",
                                "serial_number": serial_number,
                                "combined_id": combined_id,
                                "action": "FULL_ACCESS",
                                "match_method": "VID_PID_SERIAL"  }
    return updateValues 

def create_file_submission_json_cid(combined_id):
    updateValues =    {
                                "class":"ANY",
                                "vendor_name": "",
                                "product_name": "",
                                "serial_number": "",
                                "combined_id": combined_id,
                                "action": "FULL_ACCESS",
                                "match_method": "COMBINED_ID"  }
                            
    return updateValues


def package_patch_correctly(resources):
    updateValues =    {"resources": resources  }
    return updateValues


def get_device_policy_details(ids):
    # Collect Information for Device Control Policy 
    device_policy = client.get('https://api.crowdstrike.com/policy/entities/device-control/v1?ids='+ids)
    check_status(device_policy)
    return device_policy


def patch_device_id_policy(updateValues):
    # Modify the policy 
    patch_reply = client.patch('https://api.crowdstrike.com/policy/entities/device-control/v1', json=updateValues)
    check_status(patch_reply)
    patch_reply_dict = json_to_dict(patch_reply)
    patch_reply_list = unpack_resources(patch_reply_dict)
    print(patch_reply_list)
    return patch_reply_list


def insert_exceptions_update(response,updateValues):
    device_pol_data = response.json() 
    # device_pol_data['resources'][0]['settings']['classes'][0].update({'exceptions': file_info })
    device_pol_data['resources'][0]['settings']['classes'][0]['exceptions'].append(updateValues)
    return device_pol_data 

def get_device_id_policy():
    # Collect first Device Policy ID  
    device_policy_list = client.get('https://api.crowdstrike.com/policy/queries/device-control/v1')
    check_status(device_policy_list)
    device_policy_dict = json_to_dict(device_policy_list)
    device_policy_list = unpack_resources(device_policy_dict)
    a_policy = device_policy_list[0]
    return a_policy

def check_status(status_code):
    # Get HTTP Errors back for your request
    status_code.raise_for_status()

def json_to_dict(object):
    # Converts JSON output to Python Dictionary
    output = json.loads(object.text)
    # Alt method returns JSON RFC complaint text causes issues with python dict 
    # output = json.dumps(object.json()
    return output

def unpack_resources(name_of_sub):
    # Unpacks Resources Class from JSON Output - Resources general holds interesting response material in API
    resources = name_of_sub['resources']
    return resources

def unpack_errors(name_of_sub):
    errors = name_of_sub['errors']
    return errors

serial_number = '000000000620'
combined_id = '1452_33796_000000000620'


try:
    import http.client as http_client
except ImportError:
    # Python 2
    import httplib as http_client

http_client.HTTPConnection.debuglevel = 1

# You must initialize logging, otherwise you'll not see debug output.
logging.basicConfig()
logging.getLogger().setLevel(logging.DEBUG)
requests_log = logging.getLogger("requests.packages.urllib3")
requests_log.setLevel(logging.DEBUG)
requests_log.propagate = True




if __name__ == "__main__":
    if time.time() > expire:
        auth = HTTPBasicAuth(client_id, client_secret)
        client = BackendApplicationClient(client_id=client_id)
        oauth = OAuth2Session(client=client)
        token = oauth.fetch_token(token_url=token_url, auth=auth)
        client = OAuth2Session(client_id, token=token, auto_refresh_kwargs=extra, auto_refresh_url=token_url,token_updater=token_saver)
        expire = token['expires_at']
        ids = get_device_id_policy() 
        policy_details = get_device_policy_details(ids)
        policy_patch_data = insert_exceptions_update(policy_details,create_file_submission_json_sn(serial_number,combined_id))
        # policy_patch_data = insert_exceptions_update(policy_details,create_file_submission_json_cid(combined_id))
        packaged_patch = package_patch_correctly(policy_patch_data['resources'])
        packaged_patch['resources'][0]['settings']['id'] = ids














