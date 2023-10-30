# v1.0 Beta TEMP LIBs for 1Password to change with the onepassword API soon as possible!
import json, os, sys
from flask import flash
def onepassword_adsmb(username,usergroup,userpass,home_dir,email,fullname,diskkey,session_key,vault):         
    os.environ["OP_SERVICE_ACCOUNT_TOKEN"] = session_key
    # try:
    #     op = os.system('op signin -f --account '+domain+ ' --session '+session_key)
    # except Exception as e:
    #     print(e)    
    comment = "Active Directory/Samba for "+str(usergroup)
    op_adsmb_template = {
                "id": "",
                "title": usergroup,
                "version": 2,
                "vault": {
                "id": "",
                "name": vault
            },
                "category": "LOGIN",                
                "additional_information": username,
                "sections": [
            {
                "id": "add more"
            }
            ],
            "fields": [
            {                
                "type": "CONCEALED",
                "purpose": "PASSWORD",
                "label": "password",
                "value": userpass
            },
            {                
                "type": "STRING",
                "purpose": "USERNAME",
                "label": "username",
                "value": username
            },
            {
                "id": "notesPlain",
                "type": "STRING",
                "purpose": "NOTES",
                "label": "notesPlain",
                "value": str(comment)
            },
            {             
                "section": {
                "id": "add more"
                },
                "type": "STRING",
                "label": "Share",
                "value": home_dir
            },
            {             
                "section": {
                "id": "add more"
                },
                "type": "EMAIL",
                "label": "email",
                "value": email
            },
            {             
                "section": {
                "id": "add more"
                },
                "type": "STRING",
                "label": "Group",
                "value": usergroup
            },
            {                
                "section": {
                "id": "add more"
                },
                "type": "STRING",
                "label": "Fullname",
                "value": fullname                
            },
            {
                "section": {
                "id": "add more"
                },   
                "type": "CONCEALED",                
                "label": "Disk_Enc_Key",
                "value": diskkey
            }
            ]
        }
    try:        
        with open(username, "w") as jsonfile:
            myJSON = json.dump(op_adsmb_template, jsonfile) # Writing to the file                
            jsonfile.close()                        
        op_create = os.system('op item create --vault MTC --format json --template '+username)        
        # REMOVE TMP FILE
        if sys.platform.startswith('win'):
            os.system('del '+username)   
        elif sys.platform.startswith('linux'):
            os.system('rm ./'+username)   
        elif sys.platform.startswith('darwin'):
            os.system('rm ./'+username)   
        flash("Info stored in 1Password!",'success')                                   
    except Exception as e:
        flash(e,'danger') 
########################################
def onepassword_iscsi(username,usergroup,userpass,peeruser,peersecret,blockname,home_dir,email,fullname,diskkey,session_key,vault):       
    os.environ["OP_SERVICE_ACCOUNT_TOKEN"] = session_key
    # TEMPLATE NO MUTUAL CHAP
    comment = "iSCSI Target for "+str(usergroup)
    op_iscsi_template = {                
                "title": usergroup,
                "version": 2,
                "vault": {                
                "name": vault
            },
                "category": "LOGIN",                
                "additional_information": username,
                "sections": [
            {
                "id": "add more"
            }
            ],
            
            "fields": [
            {                
                "type": "STRING",
                "purpose": "USERNAME",
                "label": "User",
                "value": username
            },                
            {
                "section": {
                "id": "add more"
                },                
                "type": "CONCEALED",                
                "label": "User Secret",
                "value": userpass
            },   
            {  
                "section": {
                "id": "add more"
                },                                 
                "type": "STRING",                
                "label": "Peer User",
                "value": peeruser
            },
            {       
                "section": {
                "id": "add more"
                },            
                "type": "CONCEALED",                
                "label": "Peer Secret",
                "value": peersecret
            },
            {
                "id": "notesPlain",
                "type": "STRING",
                "purpose": "NOTES",
                "label": "notesPlain",
                "value": str(comment)
            },
            {                
                "section": {
                "id": "add more"
                },
                "type": "STRING",
                "label": "Customer Name",
                "value": fullname                
            },            
            {             
                "section": {
                "id": "add more"
                },
                "type": "EMAIL",
                "label": "Customer Email",
                "value": email
            },            
            {             
                "section": {
                "id": "add more"
                },
                "type": "STRING",
                "label": "iSCSI Target",
                "value": blockname
            },
            {             
                "section": {
                "id": "add more"
                },
                "type": "STRING",
                "label": "ZVOL",
                "value": home_dir
            },
            {
                "section": {
                "id": "add more"
                },   
                "type": "CONCEALED",                
                "label": "Disk_Enc_Key",
                "value": diskkey
            }
            ]
        }
    try:        
        with open(username, "w") as jsonfile:
            myJSON = json.dump(op_iscsi_template, jsonfile) # Writing tmp file                
            jsonfile.close()                        
        # EXEC 1PASSWORD CLI   
        op_create = os.system('op item create --vault MTC --format json --template '+username)        
        # # REMOVE TMP FILE        
        if sys.platform.startswith('win'):
            os.system('del '+username)   
        elif sys.platform.startswith('linux'):
            os.system('rm ./'+username)   
        elif sys.platform.startswith('darwin'):
           os.system('rm ./'+username)   
        flash("Info stored in 1Password!",'success')                         
    except Exception as e:
        flash("TRY",'warning')
        flash(e,'danger') 