
from oauthlib.oauth2 import BackendApplicationClient
from requests.auth import HTTPBasicAuth
from requests_oauthlib import OAuth2Session
import json
import csv

token_saver = []
 
client_id = 'c3f3a21b955149e29cac13218d160ca5'
client_secret = 'Mm3lv2f1Ce8HkUbENqW9JZSQhBua5i6V4DPs7rG0'
token_url = 'https://api.crowdstrike.com/oauth2/token'
 
auth = HTTPBasicAuth(client_id, client_secret)
client = BackendApplicationClient(client_id=client_id)
oauth = OAuth2Session(client=client)
token = oauth.fetch_token(token_url=token_url, auth=auth)

client = OAuth2Session(client_id, token=token, auto_refresh_url=token_url,token_updater=token_saver)


def create_user(firstName,lastName,uid):
	create_response = client.post('https://api.crowdstrike.com/users/entities/users/v1', json={ "firstName": firstName, "lastName": lastName, "uid": uid})
	return  create_response


def add_role(uuid,role):
	add_role_response = client.post('https://api.crowdstrike.com/user-roles/entities/user-roles/v1?user_uuid='+uuid, json={ "roleIds": role})
	print(add_role_response.status_code)
	return add_role_response


def json_to_dict(object):
	output = json.loads(object.text)
	return output

def unpack_resources(name_of_sub):
	resources = name_of_sub['resources']
	return resources

def give_me_a_value(NameOfList,Key):
    user_uuid = [d[Key] for d in NameOfList]
    return user_uuid

def convert(list_to_convert):
    b = list(list_to_convert.split())
    return b

def check_status(status_code):
	


with open('user_to_add.csv', newline='') as csvfile:
	reader = csv.DictReader(csvfile)
	line_count = 0
	for row in reader:
    	print(row['firstName'], row['lastName'])
    	firstName = (row['firstName'])
    	lastName = (row['lastName'])
    	uid = (row['uid'])
    	role = (row['role'])
    	create_response = create_user(firstName,lastName,uid)
    	response_dict = json_to_dict(create_response)
    	response_resources = unpack_resources(response_dict)
    	uuid = give_me_a_value(response_resources,'uuid')
    	uuid = listToString(uuid)
    	role = convert(role)
    	add_role(uuid,role)
    line_count += 1
    print(f'Processed {line_count} Users.')





Error checking function 201 good 400 or 404 bad. from response.status_code - split out token expiry 
Optional output verbosity, turn on dump headers, and os on 



