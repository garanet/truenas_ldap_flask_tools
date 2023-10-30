# TrueNas AD/iSCSI v1.0 Beta
import secrets,string,json,requests,re
from flask import flash, Flask
###########################################
app = Flask(__name__)
###################################### API GET/POST FUNCTION
def r_post(api_url,api_endpoint,token,data_json):    
    r = requests.post(api_url+api_endpoint, headers={'Authorization': 'Bearer {}'.format(token)}, verify=False, data=data_json)    
    if r.status_code != 200: 
        flash(r.text,'danger')
        flash("POST ERROR TO CONNECT TO THE API!!!",'warning')
    return r
def r_get(api_url,api_endpoint,token):    
    r = requests.get(api_url+api_endpoint, headers={'Authorization': 'Bearer {}'.format(token)}, verify=False)
    if r.status_code != 200: 
        flash(r.text,'danger')
        flash("GET ERROR TO CONNECT TO THE API!!!",'warning') 
    return r
####################################### PASSWORD GENERATOR (for LDAP and iSCSI user)
def password_generator(pwd_length,special_chars):
    letters = string.ascii_letters
    digits = string.digits
    if special_chars != '':
        special_chars = string.punctuation
    alphabet = letters + digits + special_chars    
    pwd = ''
    for i in range(pwd_length):
        pwd += ''.join(secrets.choice(alphabet))    
    return pwd
####################################### EMAIL FORMAT CHECK
def check_email_address(address):  
  is_valid = re.search(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,7}\b', address)
  if is_valid:
    return True
  else:
    output = ('It looks that provided email is not in correct format!')
    return output
######################################## IP FORMAT CHECK
def validate_ip(address):
    parts = address.split(".")
    if len(parts) != 4:
        flash("Wrong Format IP x.x.x.x",'danger')
        return False
    for item in parts:
        if not 0 <= int(item) <= 255:
            flash("Wrong Format IP values (255)",'danger')
            return False
    return True  
######################################## GET SYSTEM CONFIG FILE
def get_config():
    with open(".config/truenasdb", "r") as jsonfile:
        data = json.load(jsonfile)
        jsonfile.close()   
    return(data)
########################################    
def ad_cache(truenas_url,truenas_token):
    # Cache Rebuilding for TrueNAS AD
    try:                 
        r = r_get(truenas_url,'/api/v2.0/directoryservices/cache_refresh',truenas_token)                            
    except Exception as e:                        
        flash(e,'danger')
########################################