import json
import requests
import sys
import urllib
from requests.auth import HTTPBasicAuth
from base64 import b64decode

from ecdsa import SigningKey, SECP256k1

''' Disable Warnings when using verify=False'''
'''requests.packages.urllib3.disable_warnings()'''
def debug(text):
    print "[D] " + str(text)

def get_registry_auth_token(wwwauth_header, username=None, password=None, ssl=False):
    debug("get_registry_auth_token(%s)" % wwwauth_header)
    token=None
    
    import re
    pattern = 'Bearer realm="(?P<url>.*?)",service="(?P<service>.*?)",scope="(?P<scope>.*?)"'
    m = re.match(pattern, wwwauth_header)
    
    if m:
        #debug("RESULT=%s" % str(m.groups()))

        a = requests.Session()
        #debug( str(" + username=%s, password=%s" % (username, password)) )
        a.auth = HTTPBasicAuth(username, password)
        url = m.group('url') + '?service=' + urllib.quote_plus(m.group('service')) + '&scope=' + m.group('scope')
        req = a.get(url, verify=False)

        #debug('AUTH request: %s' % url)
        #debug('AUTH response: %s' % req.text)
        if (req):
            parsed_json = json.loads(req.text)
            token = parsed_json['token']
            #debug('AUTH success, token=%s' % token)

    return token



# Refer to: 
# * https://docs.docker.com/registry/spec/auth/token/
# * https://docs.docker.com/registry/spec/auth/jwt/
# * docker_auth/auth_server/server.go:CreateToken()
def rehash_registry_auth_token(strtoken):
    authtoken = None
    
    token_parts = strtoken.split('.')
    
    #debug('token.part-1: %s' % token_parts[0])
    #debug('token.part-2: %s' % token_parts[1])

    joseHdr = json.loads(b64decode(token_parts[0] + '='))
    claimSet = json.loads(b64decode(token_parts[1] + '='))
    
    debug(' + joseHdr: %s' % joseHdr)
    debug(' + claimSet: %s' % claimSet)
    
    ecdsa_key = { 'kty': 'EC', 'crv': 'P-256', 'kid': joseHdr['kid'] }
    ecdsa_key = {
    "kty": "EC",
    "crv": "P-256",
    "kid": "PYYO:TEWU:V7JH:26JV:AQTZ:LJC3:SXVJ:XGHA:34F2:2LAQ:ZRMK:Z7Q6",
    "d": "R7OnbfMaD5J2jl7GeE8ESo7CnHSBm_1N2k9IXYFrKJA",
    "x": "m7zUpx3b-zmVE5cymSs64POG9QcyEpJaYCD82-549_Q",
    "y": "dU3biz8sZ_8GPB-odm8Wxz3lNDr1xcAQQPQaOcr1fmc"
}

    sk = SigningKey.from_string( ecdsa_key['kid'], curve=SECP256k1)
   
    debug(sk)    
    
    return authtoken



def get_reqistry_request(url, username=None, password=None, ssl=False):


	req = None

	if ssl==True:
		proto="https://"
	else:
		proto="http://"

	url_endpoint = proto + url

	s = requests.Session()
	if(username!=None):
		s.auth = (username, password)

	try:
		req = s.get(url_endpoint, verify=False)
		if('Www-Authenticate' in req.headers):
			debug("WARNING: Request for auth")
			token = get_registry_auth_token(req.headers['Www-Authenticate'], username, password, ssl)
			if(token):
				token = rehash_registry_auth_token(token)
                
				s.headers.update({'Authorization': 'Bearer ' + token})
				req = s.get(url_endpoint, verify=False)
				debug("FINAL: %s" % req.text)
	except requests.ConnectionError:
		print 'Cannot connect to Registry'	

	return req



def get_registry_catalog_request(url, username=None, password=None, ssl=False):

	requrl = url+"/v2/_catalog"

	req = get_reqistry_request(requrl, username, password, ssl)
	
	return req


def get_registry_tag_request(url, repo, username=None, password=None, ssl=False):
	
	requrl = url + "/v2/" + repo  + "/tags/list"

	req = get_reqistry_request(requrl, username, password, ssl)

	return req


'''
Extracts the username and password from the url specified in case of Basic Authentication
enabled for a Docker registry

Example:-

If the url specified is like exampleuser:exampleuser@docker_registry_host:port 

then, the username is exampleuser, password is exampleuser and url is docker_registry_host:port
'''
def extract_url(url):

	uname_pwd_delimeter=":"
	auth_ip_delimeter="@"
	position_ip_delimeter=url.find(auth_ip_delimeter)

	if position_ip_delimeter==-1:
		return None, None, url
	else:
		delimiter_uname_pwd_pos = url.find(uname_pwd_delimeter)
        
		delimeter_auth_ip_pos = url.find(auth_ip_delimeter, delimiter_uname_pwd_pos)
		username = url[:delimiter_uname_pwd_pos]
		password = url[delimiter_uname_pwd_pos+1:delimeter_auth_ip_pos]
		url_endpoint = url[delimeter_auth_ip_pos+1:]
		#debug('url_endpoint=%s, username=%s, password=%s' % (url_endpoint, username, password))
		debug('url_endpoint=%s, username=%s, password=****' % (url_endpoint, username))
		return username, password, url_endpoint


def get_all_repos(url, ssl=False):
	
	username, password, url_endpoint = extract_url(url)

	req = get_registry_catalog_request(url_endpoint, username, password, ssl)

	repo_array = None
	parsed_json = None

	if(req!=None):
		parsed_json = json.loads(req.text)
	if(('errors' in parsed_json) and ('code' in parsed_json['errors'][0])):
		print "ERROR: %s" % parsed_json['errors'][0]['message']
		return []
	if('repositories' in parsed_json):
		repo_array = parsed_json['repositories']

	return repo_array



def search_for_repo(url, repo_search_name, ssl=False) :

	repo_array = get_all_repos(url, ssl);
	
	repo_dict_search = {}

	if repo_search_name in repo_array:
		parsed_repo_tag_req_resp = get_tags_for_repo(url, repo_search_name, ssl)
		repo_dict_search[repo_search_name] = parsed_repo_tag_req_resp
	else:
		''' Get all the repos '''
		repo_dict = get_all_repo_dict(url, repo_array, ssl) 

		if any(False if key.find(repo_search_name)==-1 else True for key in repo_dict) ==  True:
			print "available options:- " 
			for key in repo_dict:
				if(key.find(repo_search_name)!=-1):
					repo_dict_search[key] = get_tags_for_repo(url, key, ssl)

					
	return repo_dict_search


def get_tags_for_repo(url, repo, ssl=False):
	
	username, password, url_endpoint = extract_url(url)

	repo_tag_url_req = get_registry_tag_request(url_endpoint, repo, username, password, ssl)


	parsed_repo_tag_req_resp = json.loads(repo_tag_url_req.text)
	
	return parsed_repo_tag_req_resp["tags"]


'''
Gets the entire repository dictionary
'''
def get_all_repo_dict(url, repo_array,ssl=False):
	repo_dict = {}
	if (repo_array!=None):
		for repo in repo_array:
	 		parsed_repo_tag_req_resp = get_tags_for_repo(url, repo, ssl)
	 		repo_dict[repo] = parsed_repo_tag_req_resp

 	return repo_dict


'''
Decorates the search results to be printed on the screen
'''
def decorate_list(repo_dict):
	decorated_list_values = ""
 	
	if(len(repo_dict)==0):
		return "No results!"
		
	counter = 1;
 	for repo_key in repo_dict:
 		decorated_list_values +=  "\n-----------" + "\n" + str(counter) + ") Name: " + repo_key
 		decorated_list_values += "\nTags: "
 		counter+=1;
 		for tag in repo_dict[repo_key]:
 			decorated_list_values += tag + '\t'
 	
 	decorated_list_values += "\n\n" + str(counter-1) + " images found !"
 	return decorated_list_values


'''
Decorates the search results to be printed on the screen
'''
def decorate_html(repo_dict, regurl):
	decorated_list_values = "<html><head><title>Docker Registry Listing</title>\
	<script src='http://cdnjs.cloudflare.com/ajax/libs/list.js/1.1.1/list.min.js'></script> \
	<link rel='stylesheet' type='text/css' href='/css/browser_web.css'></head> \
	<body><h1>Docker Registry Listing</h1> \
    <div id='users'>\
  <input class='search' placeholder='Search' />\
  <button class='sort' data-sort='name'>\
    Sort by name </button>"
 	
	if(len(repo_dict)==0):
		decorated_list_values += "<p><h2>No results!</h2></p></body></html>"
		return decorated_list_values
		
	counter = 1;
	decorated_list_values += "<p><ul class='list'>"

 	for repo_key in repo_dict:
		decorated_list_values += "<li><h2 class='name'>"  + str(counter) + ". " + repo_key +"</h2>"
 		counter+=1;
 		for tag in repo_dict[repo_key]:
 			decorated_list_values += "<p class='born'><b>[" + tag + "]</b>: docker pull " + regurl + "/" + repo_key + ":" + tag + "</p><br />"
 		decorated_list_values += "</li>"
 	

 	decorated_list_values += "</ul>";
 	'''decorated_list_values += "<p><h2>" +  + " images found !" + "</h2></p>"'''
 	decorated_list_values += "<script>var options = { valueNames: [ 'name', 'born' ]}; var userList = new List('users', options);</script></body></html>"
 	
 	return decorated_list_values


def usage():
 	return "Usage: browser.py <registry_endpoint> <keyword> <value> <ssl>\
 	\nValid keywords : search, list \
 	\nValid values:- \
 	\nFor keyword search, use the value as the image name. For eg:- search redis\
 	\nFor keyword list, use the value 'all' without quotes to get a list of all the docker image repos. For eg:- list all\
 	\nFor eg:- python browser.py uname:pwd@registry_endpoint:port search busybox\
 	\nIf you use SSL, then specify 'ssl'\
 	\nFor eg:- python browser.py uname:pwd@registry_endpoint:port search busybox ssl\
 	\nFor more information, visit:- https://github.com/vivekjuneja/docker_registry_cli/"



if __name__ == "__main__":
	len_sys_argv = len(sys.argv[1:])


	if len_sys_argv < 3:
		print usage()

	elif len_sys_argv >= 3:
		commandlineargs = sys.argv[1:]
		regurl = commandlineargs[0]
		keyword = commandlineargs[1]
		repo_to_search = commandlineargs[2]
		ssl_flag  = False

		if len_sys_argv == 4:	
			ssl = commandlineargs[3]
			if ssl == "ssl":
				ssl_flag = True
		

		search_results = None

		if keyword=="search":
			search_results = search_for_repo(regurl, repo_to_search, ssl_flag)
			print decorate_list(search_results)
		elif keyword=="list":
			all_repos = get_all_repos(regurl, ssl_flag)
			search_results = get_all_repo_dict(regurl, all_repos, ssl_flag)
			print decorate_list(search_results)
		elif keyword=="html":
			all_repos = get_all_repos(regurl, ssl_flag)
			search_results = get_all_repo_dict(regurl, all_repos, ssl_flag)
			print decorate_html(search_results, regurl)
		else:
			print usage()
			sys.exit(1)

		


