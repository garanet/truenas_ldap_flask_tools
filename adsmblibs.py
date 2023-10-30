# v1.0 TrueNas AD/iSCSI 
import json, ssl
from ldap3 import Server, Connection, Tls, ALL, MODIFY_REPLACE, MODIFY_ADD, SUBTREE, ALL_ATTRIBUTES, MODIFY_REPLACE,ALL_OPERATIONAL_ATTRIBUTES, MODIFY_DELETE
from flask import flash
from commonlibs import r_post
####################################### 
def ldap_conn(ldap_admin,ldap_url,ldap_u_cn,ldap_g_cn,ldap_pwd):
    # ldap_admin = input("Please enter the AD/LDAP username: ")    
    # ldap_pwd = pwinput.pwinput(prompt='Please enter the AD/LDAP password: ', mask='*') 
    ldap_dn = 'cn='+ldap_admin
    # c = {"description": "success"}    
    t = Tls(validate=ssl.CERT_NONE)
    s = Server(host=ldap_url, tls=t)
    c = Connection(s, user=ldap_dn+','+ldap_u_cn, password=ldap_pwd, auto_bind='NONE', version=3, authentication='SIMPLE')        
    if not c.bind():
        flash('LDAP Connection Error in bind:'+c.result,'warning')
    else:
        return c
########################################
        # Add AD USER/GROUP
########################################
def ldap_user(data,username,fullname,firstname,lastname,email,home_dir,userpass):
    try:
        # Get data from the config
        data = json.loads(data)        
        ldap_url = data["ldap_url"]
        ldap_u_cn = data["ldap_u_cn"]
        ldap_g_cn = data["ldap_g_cn"]
        ldap_admin = data["ldap_admin"]
        ldap_pwd = data["ldap_pwd"]
        domain = data["domain"]
        # USER CREATION
        try:
            c = ldap_conn(ldap_admin,ldap_url,ldap_u_cn,ldap_g_cn,ldap_pwd) 
        except Exception as e:
            flash("LDAPCONN-USER",'danger')
            flash(e,'danger')                       
        c.add('CN='+username+','+ldap_u_cn, ['top', 'person', 'organizationalPerson', 'user'],                  
            {                 
                'uid': username,                    
                'displayName': fullname,
                'givenName': firstname,
                'sn': lastname,                                                                    
                'mail': email,
                'userPrincipalName': "{}@{}".format(username, domain),
                'sAMAccountName': username,                                                       
                'homeDirectory': '/'+home_dir,                     
                'userPassword': userpass                        
            })  
        flash('User '+username+' created successfully !','success')  
        result = c.result['description']             
        c.unbind() 
        return result
    except Exception as e:
        flash(e,'danger')
        c.unbind() 
########################################
def ldap_group(data,username,usergroup):         
    data = json.loads(data)                     
    ldap_url = data['ldap_url']
    ldap_u_cn = data['ldap_u_cn']
    ldap_g_cn = data['ldap_g_cn']
    ldap_admin = data['ldap_admin']
    ldap_pwd = data['ldap_pwd']
    try:
        c = ldap_conn(ldap_admin,ldap_url,ldap_u_cn,ldap_g_cn,ldap_pwd) 
    except Exception as e:        
        flash(e,'danger')
    # GROUP CREATION        
    try:
        c.add('CN='+usergroup+','+ldap_u_cn, ['group', 'top'],
            {
                'memberUid': username,
                'sAMAccountName': usergroup,
                'displayName': usergroup,
                'description': 'Customer Private Group for: '+username        
            })      
        if c.result['description'] == 'success':                                                          
            flash('Group '+usergroup+' created successfully !','success')              
        else:
            flash('Something went wrong with the GROUP in AD, check the logs', 'danger')
            flash(c.result, 'danger')    
            c.unbind()   
            return False
    except Exception as e:
        flash(e,'danger')                                     
    # ADD USER TO GROUP
    try:
        c.modify('CN='+usergroup+','+ldap_u_cn,{'member': [(MODIFY_REPLACE, ['CN='+username+','+ldap_u_cn])]})                        
    except Exception as e:
        # flash(c.result,'danger')
        flash(e,'danger') 
        c.unbind()  
    result = c.result['description']
    c.unbind()           
    return result
########################################
        # MODIFY AD USER/GROUP
########################################
def ldap_ulist(data):
    ad_cn_list = []
    try:
        # Get data from the config
        data = json.loads(data)        
        ldap_url = data["ldap_url"]
        ldap_u_cn = data["ldap_u_cn"]
        ldap_g_cn = data["ldap_g_cn"]
        ldap_admin = data["ldap_admin"]
        ldap_pwd = data["ldap_pwd"]
        domain = data["domain"]
        search_filter = "(displayName={0}*)"
        # GET AD USER LIST CREATION
        try:            
            c = ldap_conn(ldap_admin,ldap_url,ldap_u_cn,ldap_g_cn,ldap_pwd)
            # c.search(ldap_u_cn, '(objectclass=person)',attributes=['uid'])
            c.search(ldap_u_cn, search_filter = '(objectclass=person)', attributes = ['CN'])
            # c.search(search_base=ldap_u_cn,search_filter=search_filter.format('*'),search_scope=SUBTREE,attributes=ALL_ATTRIBUTES,get_operational_attributes=True)
            for entry in c.entries:
                ad_cn = entry.CN
                ad_cn_list.append(ad_cn)
            c.unbind()
            return ad_cn_list
        except Exception as e:            
            flash(e,'danger')       
    except Exception as e:        
        flash(e,'danger') 
########################################
def ldap_ugroup(data):
    ad_group_list = []
    try:
        # Get data from the config
        data = json.loads(data)        
        ldap_url = data["ldap_url"]
        ldap_u_cn = data["ldap_u_cn"]
        ldap_g_cn = data["ldap_g_cn"]
        ldap_admin = data["ldap_admin"]
        ldap_pwd = data["ldap_pwd"]
        domain = data["domain"]
        search_filter = "(displayName={0}*)"
        # GET AD USER LIST CREATION
        try:            
            c = ldap_conn(ldap_admin,ldap_url,ldap_u_cn,ldap_g_cn,ldap_pwd)
            # c.search(ldap_u_cn, '(objectclass=person)',attributes=['uid'])
            c.search(ldap_u_cn, search_filter = '(objectclass=group)', attributes = ['CN'])
            # c.search(search_base=ldap_u_cn,search_filter=search_filter.format('*'),search_scope=SUBTREE,attributes=ALL_ATTRIBUTES,get_operational_attributes=True)
            for entry in c.entries:
                ad_group = entry.CN
                ad_group_list.append(ad_group)
            c.unbind()
            return ad_group_list
        except Exception as e:            
            flash(e,'danger')       
    except Exception as e:        
        flash(e,'danger') 
########################################
def ldap_udelete(data,user):
    try:
        # Get data from the config
        data = json.loads(data)        
        ldap_url = data["ldap_url"]
        ldap_u_cn = data["ldap_u_cn"]
        ldap_g_cn = data["ldap_g_cn"]
        ldap_admin = data["ldap_admin"]
        ldap_pwd = data["ldap_pwd"]
        # GET LDAP CONN
        c = ldap_conn(ldap_admin,ldap_url,ldap_u_cn,ldap_g_cn,ldap_pwd)
        # DELTE USER
        c.delete('cn='+user+','+ldap_u_cn)
        c.unbind()        
    except Exception as e:        
        flash(e,'danger')      
########################################
def ldap_uenabledisable(data,user,nid):
    try:
        # Get data from the config
        data = json.loads(data)        
        ldap_url = data["ldap_url"]
        ldap_u_cn = data["ldap_u_cn"]
        ldap_g_cn = data["ldap_g_cn"]
        ldap_admin = data["ldap_admin"]
        ldap_pwd = data["ldap_pwd"]
        # GET LDAP CONN
        c = ldap_conn(ldap_admin,ldap_url,ldap_u_cn,ldap_g_cn,ldap_pwd)
        # LOCK THE USER            
        c.extend.microsoft.unlock_account(user='CN='+user+','+ldap_u_cn)
        # c.extend.microsoft.modify_password(user='CN='+user+','+ldap_u_cn)
        enable_account = {"userAccountControl": (MODIFY_REPLACE, [nid])}
        userdn = 'CN='+user+','+ldap_u_cn
        c.modify(userdn, changes=enable_account)
        c.unbind()
    except Exception as e:        
        flash(e,'danger')  
########################################
def ldap_uresetpwd(data,user,userpass):
    try:
        # Get data from the config
        data = json.loads(data)        
        ldap_url = data["ldap_url"]
        ldap_u_cn = data["ldap_u_cn"]
        ldap_g_cn = data["ldap_g_cn"]
        ldap_admin = data["ldap_admin"]
        ldap_pwd = data["ldap_pwd"]
        # GET LDAP CONN
        c = ldap_conn(ldap_admin,ldap_url,ldap_u_cn,ldap_g_cn,ldap_pwd)        
        # CHANGE THE USER PASSWORD                        
        c.extend.microsoft.modify_password(user='CN='+user+','+ldap_u_cn,new_password=userpass,old_password=None)
        c.unbind()
    except Exception as e:        
        flash(e,'danger')  
########################################
def ldap_modifyuser(data,username):    
    try:
        # Get data from the config
        data = json.loads(data)        
        ldap_url = data["ldap_url"]
        ldap_u_cn = data["ldap_u_cn"]
        ldap_g_cn = data["ldap_g_cn"]
        ldap_admin = data["ldap_admin"]
        ldap_pwd = data["ldap_pwd"]
        # GET AD USER LIST CREATION
        try:
            c = ldap_conn(ldap_admin,ldap_url,ldap_u_cn,ldap_g_cn,ldap_pwd)            
            c.search(ldap_u_cn,
                # search_filter=search_filter.format(username),    
                f'(CN={username})',             
                search_scope=SUBTREE,
                attributes=ALL_ATTRIBUTES,
                get_operational_attributes=True)            
            return json.loads(c.response_to_json())            
        except Exception as e:            
            flash(e,'danger')       
    except Exception as e:        
        flash(e,'danger') 
########################################
def ldap_modifyuserinfo(data,userold,username,firstname,lastname,email):    
    try:
        # Get data from the config
        data = json.loads(data)        
        ldap_url = data["ldap_url"]
        ldap_u_cn = data["ldap_u_cn"]
        ldap_g_cn = data["ldap_g_cn"]
        ldap_admin = data["ldap_admin"]
        ldap_pwd = data["ldap_pwd"]
        # RUN THE FUNCTION
        user = 'cn='+userold+','+ldap_u_cn
        usernew = 'cn='+username
        try:
            c = ldap_conn(ldap_admin,ldap_url,ldap_u_cn,ldap_g_cn,ldap_pwd)          
            c.modify(user, {'displayName': [(MODIFY_REPLACE,[username])],
                            # 'name': [(MODIFY_REPLACE,[username])],
                            # 'cn': [(MODIFY_REPLACE,[usernew])],
                            'sn': [(MODIFY_REPLACE,[firstname])],
                            'givenName': [(MODIFY_REPLACE,[lastname])],
                            'userPrincipalName': [(MODIFY_REPLACE, email)]                            
                                        })
            # MODIFY THE DN (USERNAME)
            c.modify_dn(user, usernew)
            return c            
        except Exception as e:            
            flash(e,'danger')       
    except Exception as e:        
        flash(e,'danger')         
########################################
def ldap_listrmusergroup(data,adgroup):    
    try:
        # Get data from the config
        data = json.loads(data)        
        ldap_url = data["ldap_url"]
        ldap_u_cn = data["ldap_u_cn"]
        ldap_g_cn = data["ldap_g_cn"]
        ldap_admin = data["ldap_admin"]
        ldap_pwd = data["ldap_pwd"]        
        # GET AD USER LIST CREATION
        try:             
            c = ldap_conn(ldap_admin,ldap_url,ldap_u_cn,ldap_g_cn,ldap_pwd)    
            c.search(ldap_u_cn,
                # search_filter=search_filter.format(username),    
                f'(CN={adgroup})',  
                # search_filter='(|(&(objectClass=*)(member=uid='+adgroup+','+ldap_u_cn+')))',       
                search_scope=SUBTREE,
                attributes=ALL_ATTRIBUTES,
                get_operational_attributes=True)              
            for entry in c.response:
                result = entry['attributes']            
            c.unbind()            
        except Exception as e:            
            flash(e,'danger')       
    except Exception as e:        
        flash(e,'danger')         
    return result
########################################
def ldap_addusergroup(data,adgroup,adusergroup):     
    try:        
        # Get data from the config
        data = json.loads(data)        
        ldap_url = data["ldap_url"]
        ldap_u_cn = data["ldap_u_cn"]
        ldap_g_cn = data["ldap_g_cn"]
        ldap_admin = data["ldap_admin"]
        ldap_pwd = data["ldap_pwd"]        
        # REMOVE USER FROM GROUP        
        try:             
            c = ldap_conn(ldap_admin,ldap_url,ldap_u_cn,ldap_g_cn,ldap_pwd)                
            user = "CN="+adusergroup+","+ldap_u_cn
            group = "CN="+adgroup+","+ldap_u_cn
            c.extend.microsoft.add_members_to_groups(user,group)                
            c.unbind()                
        except Exception as e:               
            flash(e,'danger')       
    except Exception as e:        
        flash(e,'danger')         
    return c  
########################################
def ldap_rmusergroup(data,adgroup,adusergroup):    
    try:
        # Get data from the config
        data = json.loads(data)        
        ldap_url = data["ldap_url"]
        ldap_u_cn = data["ldap_u_cn"]
        ldap_g_cn = data["ldap_g_cn"]
        ldap_admin = data["ldap_admin"]
        ldap_pwd = data["ldap_pwd"]        
        # REMOVE USER FROM GROUP        
        try:             
            c = ldap_conn(ldap_admin,ldap_url,ldap_u_cn,ldap_g_cn,ldap_pwd)                
            user = "CN="+adusergroup+","+ldap_u_cn
            group = "CN="+adgroup+","+ldap_u_cn
            c.extend.microsoft.remove_members_from_groups(user,group)                                                           
            c.unbind()                
        except Exception as e:               
            flash(e,'danger')       
    except Exception as e:        
        flash(e,'danger')         
    return c
########################################
def ldap_rmgroup(data,adgroup):        
    try:        
        # Get data from the config
        data = json.loads(data)        
        ldap_url = data["ldap_url"]
        ldap_u_cn = data["ldap_u_cn"]
        ldap_g_cn = data["ldap_g_cn"]
        ldap_admin = data["ldap_admin"]
        ldap_pwd = data["ldap_pwd"]        
        # GET AD USER LIST CREATION
        try:             
            c = ldap_conn(ldap_admin,ldap_url,ldap_u_cn,ldap_g_cn,ldap_pwd)    
            adgroup = 'CN='+adgroup+','+ldap_u_cn            
            c.delete(adgroup)   
            result = c.result                     
            c.unbind()               
            return result            
        except Exception as e:            
            flash(e,'danger')       
    except Exception as e:        
        flash(e,'danger')     
########################################
def ldap_renamegroup(data,adgroupold,adgroupnew):        
    try:
        # Get data from the config
        data = json.loads(data)        
        ldap_url = data["ldap_url"]
        ldap_u_cn = data["ldap_u_cn"]
        ldap_g_cn = data["ldap_g_cn"]
        ldap_admin = data["ldap_admin"]
        ldap_pwd = data["ldap_pwd"]        
        # GET AD USER LIST CREATION
        try:             
            c = ldap_conn(ldap_admin,ldap_url,ldap_u_cn,ldap_g_cn,ldap_pwd)    
            adgroup = 'CN='+adgroupold+','+ldap_u_cn            
            c.modify_dn(adgroup,'cn='+adgroupnew)            
            result = c.result
            c.unbind()               
            return result            
        except Exception as e:            
            flash(e,'danger')       
    except Exception as e:        
        flash(e,'danger')  
        
########################################
        # ADD SAMBA DATASET
########################################
def ad_dataset(encryption,truenas_pool,home_dir,fullname,email,quota,refquota,recordsize,truenas_url,truenas_token):
    # DATASET JSON CONFIG
    try:
        if encryption == 'NO':
            poolnas = {        
                "name" : truenas_pool+"/"+home_dir,
                "comments" : fullname+" "+email,
                "compression" : "LZ4",
                "sync" : "STANDARD",
                "atime" : "OFF",
                "copies" : 1,
                "quota" : int(quota),        
                "refquota" : int(refquota),        
                "deduplication" : "OFF",
                "exec" : "ON",
                "snapdir" : "HIDDEN",
                "readonly" : "OFF",
                "recordsize" : recordsize,
                "casesensitivity" : "SENSITIVE", 
                "inherit_encryption": False,
                "encryption" : False                
            }            
        else: 
            poolnas = {        
                "name" : truenas_pool+"/"+home_dir,
                "comments" : fullname+" "+email,
                "compression" : "LZ4",
                "sync" : "STANDARD",
                "atime" : "OFF",
                "copies" : 1,
                "quota" : int(quota),        
                "refquota" : int(refquota),        
                "deduplication" : "OFF",
                "exec" : "ON",
                "snapdir" : "HIDDEN",
                "readonly" : "OFF",
                "recordsize" : recordsize,
                "casesensitivity" : "SENSITIVE", 
                "inherit_encryption": False,
                "encryption" : True,
                "encryption_options" : {"generate_key":True}
            }
    except Exception as e:                
        flash(e,'danger')   
    # POST DATASET CREATION
    try:
        data_json = json.dumps(poolnas)   
        r = r_post(truenas_url,'/api/v2.0/pool/dataset',truenas_token,data_json)                                                                           
    except Exception as e:                
        flash(e,'danger')    
########################################
def ad_smb(hostsallow,hostsdeny,username,truenas_pool,home_dir,truenas_url,truenas_token):
    try:             
        share = {       
            "purpose": "PRIVATE_DATASETS",
            "path" : "/mnt/"+truenas_pool+"/"+home_dir,
            "name": username,
            "path_suffix": "%U",        
            "home": True,        
            "comment": "Shares for "+username,
            "ro": False,
            "browsable": True,
            "recyclebin": False,
            "guestok": False,
            "hostsallow": hostsallow,
            "hostsdeny": hostsdeny,
            "auxsmbconf": "",
            "aapl_name_mangling": False,
            "abe": False,
            "acl": True,
            "durablehandle": True,
            "streams": True,
            "timemachine": False,
            "timemachine_quota": 0,
            "shadowcopy": True,
            "fsrvp": False,
            "enabled": True,
            "cluster_volname": "",
            "afp": False                  
        }                  
        data_json = json.dumps(share)    
        r = r_post(truenas_url,'/api/v2.0/sharing/smb',truenas_token,data_json)                                     
    except Exception as e:                
        flash(e,'danger')       
########################################
def ad_acl(username,usergroup,truenas_url,truenas_pool,home_dir,truenas_token):
    # CALL THE SHARE ACL FUNCTION                                                           
    acl = { 
        "user": username,  
        "group": usergroup,            
        "options": {
        "set_default_acl": False,
        "recursive": True,
        "traverse": False
        }
    }    
    # Apply Permissions to the pool
    try:
        data_json = json.dumps(acl)          
        r = r_post(truenas_url,'/api/v2.0/pool/dataset/id/'+truenas_pool+'%2F'+home_dir+'/permission',truenas_token,data_json)                                                                           
    except Exception as e:                        
        flash(e,'danger')                
########################################
def get_dataset_key(home_dir,truenas_pool,truenas_url,truenas_token):
    # Getting the Encryption Key to store it in OnePassword
    try:
        key = {             
            "id": truenas_pool+'/'+home_dir,
            "download": True
        }      
        data_json = json.dumps(key)     
        r = r_post(truenas_url,'/api/v2.0/pool/dataset/export_key',truenas_token,data_json)
        key = r.content.decode("utf-8")       
        key = json.loads(key)    
        diskkey = key[truenas_pool+'/'+home_dir] 
    except Exception as e:                    
        flash(e,'danger')     
    return diskkey
########################################