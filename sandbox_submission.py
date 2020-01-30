
#!/usr/bin/python 

""" 

Script to submit file to Sandbox and get status, and report 


- Act on IOC submit to Custom IOC or similar  


"""




from oauthlib.oauth2 import BackendApplicationClient
from requests.auth import HTTPBasicAuth
from requests_oauthlib import OAuth2Session
import json
from IPython.core.debugger import set_trace
import time
from time import sleep 
import hashlib 


token_saver = []
expire = 0

 
client_id = 'c3f3a21b955149e29cac13218d160ca5'
client_secret = 'Mm3lv2f1Ce8HkUbENqW9JZSQhBua5i6V4DPs7rG0'
token_url = 'https://api.crowdstrike.com/oauth2/token'

extra = {
'client_id': client_id,
'client_secret': client_secret,
 }
 

# client = ''


# def token_produce(client,expire,extra,client_id,client_secret,token_url):
if time.time() > expire:
	auth = HTTPBasicAuth(client_id, client_secret)
	client = BackendApplicationClient(client_id=client_id)
	oauth = OAuth2Session(client=client)
	token = oauth.fetch_token(token_url=token_url, auth=auth)
	client = OAuth2Session(client_id, token=token, auto_refresh_kwargs=extra, auto_refresh_url=token_url,token_updater=token_saver)
	expire = token['expires_at']
	# return expire,client 

def upload_file(filename):
	data = open(filename, 'rb').read()
	upload_file = client.post('https://api.crowdstrike.com/samples/entities/samples/v2?file_name='+filename,data=data,headers={'Content-Type': 'application/octet-stream'})
	check_status(upload_file)


def submit_file(file_info):
	submit_file = client.post('https://api.crowdstrike.com/falconx/entities/submissions/v1', json=file_info)
	check_status(submit_file)
	return submit_file

def check_file_progress(ids):
	get_progress = client.get('https://api.crowdstrike.com/falconx/entities/submissions/v1?ids='+ids)
	check_status(get_progress)
	return get_progress

def get_summary_report(ids):
	get_summary_report = client.get('https://api.crowdstrike.com/falconx/entities/report-summaries/v1?ids='+ids)
	check_status(get_summary_report)
	return get_summary_report

def get_full_report(ids):
	/falconx/queries/reports/v1?filter='submit_name': '69516a84c00cf22fc911db555d024efb8a290951d955a5e37c635639bebb2cd9_TAvW58DXEE'
	get_full_report = client.get('https://api.crowdstrike.com/falconx/entities/reports/v1?ids='+ids)
	check_status(get_summary_report)
    return get_full_report


def get_full_report(ids):
	# Get other data need filter list 
	get_full_report = client.get('https://api.crowdstrike.com/falconx/entities/artifacts/v1?ids='+ids)
	check_status(get_full_report)
	return get_full_report
	

def calculate_sh256(filename):
	# Only for small files
	with open(filename,"rb") as f:
		bytes = f.read() # read entire file as bytes
		readable_hash = hashlib.sha256(bytes).hexdigest();
		print(readable_hash)
	return(readable_hash)

def create_file_submission_json(filename):
	sha256 = calculate_sh256(filename)
	file_info = {
    "sandbox": [{
        "sha256": sha256,
        "environment_id": 100,
        "submit_name": filename
    }]
}
	return file_info 


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

def get_status_submission(name_of_sub):
	progress = name_of_sub['meta']['quota']['in_progress']
	return progress

def unpack_job_id(name_of_sub):
	id = name_of_sub['resources'][0]['id']
	return id


def create_ioc_submission_json(typeIOC,valueIOC):
	file_info =    { [ {
        # "batch_id": "<string>",
        # "created_by": "<string>",
        # "created_timestamp": "<string>",
        # "description": "<string>",
        # "expiration_days": "<integer>",
        # "expiration_timestamp": "<string>",
        # "modified_by": "<string>",
        # "modified_timestamp": "<string>",
        # "policy": "<string>",
        # "share_level": "<string>",
        # "source": "<string>",
        "type": typeIOC,
        "value": value
                            } ] }
	return file_info 


if __name__ == "__main__":
	# expire,client = token_produce(client,expire,extra,client_id,client_secret,token_url)
	filename = '69516a84c00cf22fc911db555d024efb8a290951d955a5e37c635639bebb2cd9_TAvW58DXEE'
	upload_file(filename)
	file_info = create_file_submission_json(filename)
	submit_info = submit_file(file_info)
	submit_dict = json_to_dict(submit_info)
	id = unpack_job_id(submit_dict)
	sleep(900)
	file_status = check_file_progress(id)
	file_progress = json_to_dict(file_status)
	if get_status_submission(file_progress) == 1:
		print('In Progress')
	else: 
		print('Done')
	summary_report = get_summary_report(id)
	summary_info = json_to_dict(summary_report)
	full_report = get_full_report(id)
	full_info = json_to_dict(full_report)
	# Collect the IOC and Submit (should check for IOC prior to or does system do it)



