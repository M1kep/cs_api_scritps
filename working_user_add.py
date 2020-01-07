
#!/usr/bin/python 

"""Simple Script to Create Users using CrowdStrike Falcon API """


from oauthlib.oauth2 import BackendApplicationClient
from requests.auth import HTTPBasicAuth
from requests_oauthlib import OAuth2Session
import json
import csv
from IPython.core.debugger import set_trace


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
	print ('Creating Account')
	check_status(create_response)
	return create_response


def add_role(uuid,role):
	add_role_response = client.post('https://api.crowdstrike.com/user-roles/entities/user-roles/v1?user_uuid='+uuid, json={ "roleIds": role})
	check_status(add_role_response)
	print ('Applying Role')
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
	status_code.raise_for_status()

def listToString(s):  
    str1 = ""  
    
    for ele in s:  
        str1 += ele   
    
    return str1

def check_for_existing_user(firstName,lastName,uid):
	user_check = client.get('https://api.crowdstrike.com/users/queries/emails-by-cid/v1')
	user_check_dict = json_to_dict(user_check)
	user_check_list = unpack_resources(user_check_dict)
	if uid in user_check_list:
			#print("User has account check", uid)
			user_exists = 'true'
	else:
			#print("User needs account created", uid)
			user_exists = 'false'
	return user_exists

def manage_user_creation(firstName,lastName,uid):
	create_response = create_user(firstName,lastName,uid)
	response_dict = json_to_dict(create_response)
	response_resources = unpack_resources(response_dict)
	print(response_resources)
	uuid = give_me_a_value(response_resources,'uuid')
	uuid = listToString(uuid)
	return uuid



if __name__ == "__main__":
	with open('user_to_add.csv', newline='') as csvfile:
		reader = csv.DictReader(csvfile)
		line_count = 0
		for row in reader:
			firstName = (row['firstName'])
			lastName = (row['lastName'])
			uid = (row['uid'])
			role = (row['role'])
			user_exists = check_for_existing_user(firstName,lastName,uid)
			if user_exists =='false':
				set_trace()
				uuid = manage_user_creation(firstName,lastName,uid)
				role = convert(role)
				add_role(uuid,role)
				line_count += 1
				print('User Created',uid)
				print('User Added with role',role)
			else:
				print('User Exists,',uid)
		print(f'Processed {line_count} Users.')