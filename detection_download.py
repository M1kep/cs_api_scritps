
#!/usr/bin/python 

""" 

Script to collect Detections and then Network Contain 

- Add Menu and Script

- Add better selection methods 

- For Loop for dealing with multiple detections 


"""



from oauthlib.oauth2 import BackendApplicationClient
from requests.auth import HTTPBasicAuth
from requests_oauthlib import OAuth2Session, TokenUpdated
import json
import csv
# Add below for ability to debug better 
from IPython.core.debugger import set_trace
import time 


token_saver = []

 
client_id = '7b04838f657144dd8b0ec203555d19a1'
client_secret = 'AOf8bsdNMe61Fa0LI5Y2jhCnq3mcy947VPvkBKJZ'
token_url = 'https://api.crowdstrike.com/oauth2/token'

extra = {
'client_id': client_id,
'client_secret': client_secret,
 }
 
expire = 0
# auth = HTTPBasicAuth(client_id, client_secret)
# client = BackendApplicationClient(client_id=client_id)
# oauth = OAuth2Session(client=client)
# token = oauth.fetch_token(token_url=token_url, auth=auth)

client = ''

# client = OAuth2Session(client_id, token=token, auto_refresh_kwargs=extra, auto_refresh_url=token_url,token_updater=token_saver)



def token_produce(client,expire,extra,client_id,client_secret,token_url):
	if time.time() > expire:
		auth = HTTPBasicAuth(client_id, client_secret)
		client = BackendApplicationClient(client_id=client_id)
		oauth = OAuth2Session(client=client)
		token = oauth.fetch_token(token_url=token_url, auth=auth)
		client = OAuth2Session(client_id, token=token, auto_refresh_kwargs=extra, auto_refresh_url=token_url,token_updater=token_saver)
		expire = token['expires_at']
		return expire,client 



def get_detections():
	detect = client.get('https://api.crowdstrike.com/detects/queries/detects/v1')
	check_status(detect)
	detect_dict = json_to_dict(detect)
	detect_list = unpack_resources(detect_dict)
	print(detect_list)
	return detect_list

def contain_asset(aid):
	contain = client.post('https://api.crowdstrike.com/devices/entities/devices-actions/v2?action_name=contain', json={"ids": aid})
	check_status(contain)


def get_detections1():
	#Limited to first one 
	print ('Requesting one Detections')
	detect = client.get('https://api.crowdstrike.com/detects/queries/detects/v1?limit=1')
	check_status(detect)
	detect_dict = json_to_dict(detect)
	detect_list = unpack_resources(detect_dict)
	return detect_list,detect_dict


def get_detect_details(id):
	get_detects_info = client.post('https://api.crowdstrike.com/detects/entities/summaries/GET/v1', json={ "ids": id})
	print ('Requesting_detect Details')
	check_status(get_detects_info)
	detect_dict = json_to_dict(get_detects_info)
	detect_list = unpack_resources(detect_dict)
	return detect_list


def convert(list_to_convert):
	# Convert String to List 
    b = list(list_to_convert.split())
    return b

def check_status(status_code):
	# Get HTTP Errors back for your request
	status_code.raise_for_status()

def json_to_dict(object):
	# Converts JSON output to Python Dictionary
	output = json.loads(object.text)
	return output

def unpack_resources(name_of_sub):	
	resources = name_of_sub['resources']
	return resources

def unpack_errors(name_of_sub):
	errors = name_of_sub['errors']
	return errors

def unpack_aid(detect_list):
    aid = detect_list[0]['device']['device_id']
    aid = convert(aid)
    return aid


if __name__ == "__main__":
	expire,client = token_produce(client,expire,extra,client_id,client_secret,token_url)
	detects_list,detects_dict = get_detections1()
	alot_of_detects = get_detect_details(detects_list)
	aid = unpack_aid(alot_of_detects)
	contain_asset(aid)

