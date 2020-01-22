
from oauthlib.oauth2 import BackendApplicationClient
from requests.auth import HTTPBasicAuth
from requests_oauthlib import OAuth2Session
import json
import csv
from IPython.core.debugger import set_trace



expire = 0


def token_produce(expire,extra,client_id,client_secret,token_url):
	if time.time() > expire:
		auth = HTTPBasicAuth(client_id, client_secret)
		client = BackendApplicationClient(client_id=client_id)
		oauth = OAuth2Session(client=client)
		token = oauth.fetch_token(token_url=token_url, auth=auth)
		client = OAuth2Session(client_id, token=token, auto_refresh_kwargs=extra, auto_refresh_url=token_url,token_updater=token_saver)
		expire = token['expires_at']
		return expire,client 

"""Requires ANY Class to be default Permit"""




def create_file_submission_json(serial_number):
	updateValues =    [ 
                                "vendor_name": "",
                                "product_name": "",
                                "serial_number": serial_number,
                                "combined_id": "",
                                "action": "FULL_ACCESS",
                                "match_method": "VID_PID_SERIAL"  ]
                            
	return updateValues 




def get_device_id_policy(ids):
	# Collect Information for Device Control Policy 
	device_policy = client.get('https://api.crowdstrike.com/policy/entities/device-control/v1?ids='+ids)
	check_status(device_policy)
	return device_policy




def patch_device_id_policy(updateValues):	
	# Modify the policy 
	patch_reply = client.patch('https://api.crowdstrike.com/policy/entities/device-control/v1', json=file_info)
	check_status(patch_reply)
	patch_reply_dict = json_to_dict(patch_reply)
	patch_reply_list = unpack_resources(patch_reply_dict)
	print(patch_reply_list)
	return patch_reply_list


def insert_exceptions_update(response,updateValues):
	json_data = device_policy.json() 
	json_data['resources'][0]['settings']['classes'][0].update({'exceptions': file_info })
	return json_data 



serial_number = ''


if __name__ == "__main__":
	expire,client = token_produce(expire,extra,client_id,client_secret,token_url)












