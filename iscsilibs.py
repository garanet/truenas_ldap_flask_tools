# TrueNas AD/iSCSI v1.0 Beta
import json,ast
from flask import flash
from commonlibs import r_get, r_post
########################################
def truenas_iscsi_init(iscsi_initiator,item_iqn_initiator,add_cliqn_initiator,iscsi_portal,truenas_url,truenas_token,blockname,auth_networks,iscsi_meth,iscsi_disc_meth):
    # FORM CHECKS / TO REVIEW
    init_list_text = 'Select it from the list or press + for a new one'     
    # CREATE A NEW INITIATOR WITH NEW IQN
    if iscsi_initiator == init_list_text: 
        try:
            iscsi_initiator = item_iqn_initiator
            iscsi_init_list =   {                        
                "initiators": 
                    iscsi_initiator,
                "comment": add_cliqn_initiator
            }                
            # CREATE THE INITIATOR
            data_json = json.dumps(iscsi_init_list)                     
            r = r_post(truenas_url,'/api/v2.0/iscsi/initiator',truenas_token,data_json)             
            # CREATE THE TARGET
            iscsi_portal = ast.literal_eval(iscsi_portal)           
            iscsi_portal = iscsi_portal['id']           
            # GET NEW iscsi_initiator ID
            iscsi_initiator_id = json.loads(r.text)
            iscsi_initiator_id = iscsi_initiator_id['id']            
            # CREATE NEW TARGET
            results = truenas_iscsi_target(blockname,add_cliqn_initiator,iscsi_initiator_id,auth_networks,iscsi_portal,iscsi_meth,iscsi_disc_meth,truenas_url,truenas_token)             
            return results
        except Exception as e:            
            flash(e,'danger')     
    else: # CREATE A NEW INITIATOR WITH OLD IQN        
        try: # SANITAZE iscsi_initiator
            iscsi_portal = ast.literal_eval(iscsi_portal)           
            iscsi_portal = iscsi_portal['id']
            iscsi_initiator = ast.literal_eval(iscsi_initiator)
            iscsi_initiator_id = int(iscsi_initiator['id'])            
            add_cliqn_initiator = iscsi_initiator['comment']
        except Exception as e:            
            flash(e,'danger')        
        # CREATE THE TARGET    
        try:
            results = truenas_iscsi_target(blockname,add_cliqn_initiator,iscsi_initiator_id,auth_networks,iscsi_portal,iscsi_meth,iscsi_disc_meth,truenas_url,truenas_token)                        
            return results
        except Exception as e:            
            flash(e,'danger')
########################################
def truenas_iscsi_zvol(encryption,truenas_pool,home_dir,volsize,truenas_url,truenas_token,username,userpass,peeruser,peersecret):
    # CHECKING DISK ENCRYPTION IF ENABLED
    if encryption == 'no' or encryption == 'NO':             
        poolnas = {        
            "name" : truenas_pool+"/"+home_dir,
            "comments" : "",
            "type": "VOLUME",
            "compression" : "LZ4",                    
            "sync" : "STANDARD",
            "volsize" : volsize,  
            "volblocksize": "64K",
            "snapdev" : "HIDDEN",
            "readonly" : "OFF",
            "inherit_encryption": False,
            "encryption" : False                
        }            
    else: 
        poolnas = {        
            "name" : truenas_pool+"/"+home_dir,
            "comments" : "",
            "type": "VOLUME",
            "compression" : "LZ4",                    
            "sync" : "STANDARD",
            "volsize" : volsize,  
            "volblocksize": "64K",
            "snapdev" : "HIDDEN",
            "readonly" : "OFF",
            "inherit_encryption": False,
            "encryption" : True,
            "encryption_options" : {"generate_key": True}
        }
    # GET THE LAST GROUP ID
    try:
        r = r_get(truenas_url,'/api/v2.0/iscsi/auth',truenas_token)
        r_json = r.json()                                 
        groupid = r_json[0]             
        sorted_a = sorted(r_json, key=lambda k: k['id'], reverse=True)
        groupid = sorted_a[0]['id'] + 1 # PROGRESSIVE GID/LUA                                            
    except Exception as e: 
        groupid = 1 # IF IS EMPTY           
        flash(e,'danger')                                                
    # CREATE ZVOL        
    try: 
        data_json = json.dumps(poolnas)   
        r = r_post(truenas_url,'/api/v2.0/pool/dataset',truenas_token,data_json)
    except Exception as e:                 
        flash(e,'danger')   
    # ADD USER AND PEERUSER                           
    if r.status_code == 200:          
        try: 
            # MUTUAL CHAP
            if peersecret != "":
                iscsi_auth_user = {
                    "tag": groupid,
                    "user": username,
                    "secret": userpass,
                    "peeruser": peeruser,
                    "peersecret": peersecret
                }                             
            else: # CHAP  / NONE  
                iscsi_auth_user = {
                    "tag": groupid,
                    "user": username,
                    "secret": userpass                                    
                }  
            data_json = json.dumps(iscsi_auth_user)                              
            r = r_post(truenas_url,'/api/v2.0/iscsi/auth',truenas_token,data_json)
        except Exception as e:                            
            flash(e,'danger')        
        return data_json        
########################################
def truenas_iscsi_extent(blockname,username,groupid,extenttype,truenas_pool,home_dir,truenas_url,truenas_token):      
    try:    
        if extenttype == 'd': # DISK
            extenttype = "DISK"
            iscsi_zvol = "zvol/"+truenas_pool+"/"+home_dir
            iscsi_instance = {        
                "name": blockname,        
                "type": extenttype,
                "disk": iscsi_zvol,            
                "blocksize": 512,
                "pblocksize": False,
                "serial": int(groupid),
                "comment": username,        
                "insecure_tpc": True,
                "xen": False,
                "ro": False,
                "rpm": "SSD",
                "enabled": True
                }
        elif extenttype == 'f':  # FILE
            extenttype = "FILE"
            iscsi_zvol = "zvol/"+truenas_pool+"/"+home_dir 
            iscsi_instance = {        
                "name": blockname,        
                "type": extenttype,
                "disk": iscsi_zvol,
                "path": "/mnt/"+truenas_pool+"/"+home_dir,
                "filesize": "0",
                "blocksize": 512,
                "pblocksize": False,
                "serial": int(groupid),
                "comment": username,        
                "insecure_tpc": True,
                "xen": False,
                "ro": False,
                "rpm": "SSD",
                "enabled": True
                }
    except Exception as e:        
        flash(e,'danger')              
    try:
        data_json = json.dumps(iscsi_instance)   
        r = r_post(truenas_url,'/api/v2.0/iscsi/extent',truenas_token,data_json)        
    except Exception as e:        
        flash(e,'danger')      
    return r.text
########################################
# POST THE CONFIG VIA API
def truenas_iscsi_target(blockname,comment,iscsi_initiator,auth_networks_ip,iscsi_portal,iscsi_meth,iscsi_disc_meth,truenas_url,truenas_token):
    # MAKE THE JSON API FROM VALUES
    try:        
        iscsi_instance = {
            "name": blockname,
            "alias": "",
            "mode": "ISCSI",
            "auth_networks": auth_networks_ip,
            "groups": [
                {
                    "portal": iscsi_portal,
                    "initiator": iscsi_initiator,
                    "auth": iscsi_meth,
                    "authmethod": iscsi_disc_meth
                }
            ]
        }  
    except Exception as e:        
        flash(e,'danger')      
    try:
        data_json = json.dumps(iscsi_instance)
        r = r_post(truenas_url,'/api/v2.0/iscsi/target',truenas_token,data_json)                                   
    # RETRIVE THE USER INFO
        r = r_get(truenas_url,'/api/v2.0/iscsi/auth',truenas_token)                         
        r_json = r.json()                            
        iscsi_user_info = sorted(r_json, key=lambda k: k['id'], reverse=True)    
        iscsi_user_info = iscsi_user_info[0]                                           
    except Exception as e:        
        flash(e,'danger')
    # Associated Targets
    try:
        r = r_get(truenas_url,'/api/v2.0/iscsi/target',truenas_token)
        r_json = r.json()                            
        targetid = r_json[0]             
        sorted_a = sorted(r_json, key=lambda k: k['id'], reverse=True)
        targetid = sorted_a[0]['id']             
    except Exception as e:              
        flash(e,'danger')
    try:
        r = r_get(truenas_url,'/api/v2.0/iscsi/extent',truenas_token)
        r_json = r.json()                            
        extentid = r_json[0]             
        sorted_a = sorted(r_json, key=lambda k: k['id'], reverse=True)
        extentid = sorted_a[0]['id']             
    except Exception as e:                  
        flash(e,'danger')    
    try:        
        iscsi_associated =   {
            "extent": extentid,
            "target": targetid
        }
        data_json = json.dumps(iscsi_associated)   
        r = r_post(truenas_url,'/api/v2.0/iscsi/targetextent',truenas_token,data_json)  
    except Exception as e:
        flash(e,'danger')           
    return (iscsi_instance)