# TrueNas AD/iSCSI
from flask import Flask, render_template, request, flash, redirect, url_for, session
from time import sleep
from cryptography.fernet import Fernet
import sys,secrets,uuid,json,requests,ast
# CUSTOM LIBS
from commonlibs import * # common libs
from adsmblibs import * # iscsi libs
from iscsilibs import * # iscsi libs
from oplibs import * # op libs (to review/API)
# sys.set_int_max_str_digits(1073741824)
requests.urllib3.disable_warnings() # Only for test, to avoid warning errors for http
###########################################
app = Flask(__name__)
app.config.from_pyfile("./cfg/config.py")
###########################################
#  Welcome Page
###########################################
@app.route('/')
def index():      
    return render_template('index.html')
###########################################
# Route for handling the login page
###########################################
@app.route('/login', methods=['GET', 'POST'])
def login():    
    session.pop('id', None) # remove session id for logout
    if request.method == 'POST':
        if request.form['userkey'] == '':
            flash('Insert the Password Key.','warning')
        else: # Decrypt config file base on the password key
            try:
                fernet = Fernet(request.form['userkey'])                                       
                with open(app.config['CONFIG_FOLDER']+'truenasdb', 'rb') as enc_file:
                    encrypted = enc_file.read()                
                    decrypted = fernet.decrypt(encrypted)      
                    enc_file.close()                    
                session['id'] = str(uuid.uuid4())                          
                app.config['DECRYPTED'] = decrypted.decode('utf-8')                
                return render_template('index.html')        
            except Exception as e:
                flash('Invalid Credentials. Please try again.','danger')                
    return render_template('login.html',spinner='login')
###########################################
# ACTIVE DIRECTORY AND SMB USER FUNCTIONS #
###########################################
@app.route('/aduser', methods=('GET', 'POST'))
def aduser_data():
    # CHECKING SESSION
    if not 'id' in session or app.config['DECRYPTED'] == []:
        return redirect(url_for('login'))           
    else:                
        if request.method == 'POST':       
            # GET INFO FROM POSTED FORM
            username = request.form['username'].lower().strip()
            firstname = request.form['firstname']
            lastname = request.form['lastname']
            email = request.form['email'].lower().strip()
            cusergroup = request.form['cusergroup']        
            usergroup = username # keeps the username without UUID
            # GENERATE SECRETS and UUID
            username = username+'-'+secrets.token_hex(3)
            userpass = password_generator(12,'y')            
            fullname = firstname+' '+lastname        
            home_dir = usergroup+'-'+str(uuid.uuid4()) 
            # VERIFIY IF ALL FIELDS FILLED
            if not username or not firstname or not lastname or not email or not cusergroup:
                flash('Please fill all required fields!','warning')
            else:
                # Email validation
                if check_email_address(email) != True:
                    output = check_email_address(email)
                    flash(output,'danger')
                else:
                # Get data from the config
                    data = app.config['DECRYPTED']                            
                # AD USER CREATION
                    userpass = password_generator(12,'y')            
                    fullname = firstname+' '+lastname        
                    home_dir = usergroup+'-'+str(uuid.uuid4())                 
                # LDAP USER CREATION   
                    try:           
                        res_ldap_user = ldap_user(data,username,fullname,firstname,lastname,email,home_dir,userpass) 
                    except Exception as e:
                        flash(e,'danger')   
                        return render_template('aduser.html')                       
                # CHECKING IF CREATE GROUP OR NOT
                    if res_ldap_user == 'success': 
                        app.config['ADSMBUSERN'] = username
                        app.config['ADSMBGROUP'] = usergroup
                        app.config['ADSMBUSPWD'] = userpass
                        app.config['ADSMBFULNM'] = fullname
                        app.config['ADSMBHOMED'] = home_dir
                        app.config['ADSMBEMAIL'] = email                                               
                        if cusergroup == 'NO':      
                            flash('User '+username+' created successfully without Group creation!','success')
                            # SETUP TRUENAS DATASET                        
                            return redirect(url_for('addataset_data', job="addataset", spinner='addataset_data'))   
                        else:
                            try:
                                # GROUP CREATION
                                ldap_group(data,username,usergroup)
                            except Exception as e:
                                flash('Something went wrong USER/AD, check the logs','danger')
                                flash(e,'danger')
                                return render_template('aduser.html')
                            # SETUP TRUENAS DATASET   
                            return redirect(url_for('addataset_data', job="addataset", spinner='addataset_data'))          
    return render_template('aduser.html')
########################################
@app.route('/addataset', methods=('GET', 'POST'))
def addataset_data():
    # VERIFY SESSION ID
    if not 'id' in session or app.config['DECRYPTED'] == []:
        return redirect(url_for('login'))           
    else:     
        data = app.config['DECRYPTED']        
        data = json.loads(data)
        truenas_url = data['truenas_url'] 
        truenas_pool = data['truenas_pool']        
        truenas_token = data['truenas_token']        
        job = request.args.get('job')
        # VERIFY JOB STEP
        if job != 'addataset':
            return redirect(url_for('aduser_data'))           
        else:      
        # GET VALUES FROM THE PREVIOUS APP.CONFIG
            username = app.config['ADSMBUSERN']
            usergroup = app.config['ADSMBGROUP']
            userpass = app.config['ADSMBUSPWD']
            fullname = app.config['ADSMBFULNM']
            home_dir = app.config['ADSMBHOMED']
            email = app.config['ADSMBEMAIL']            
        # EXEC IF POST
            if request.method == 'POST':       
                quota_tmp = request.form['quota_tmp']
                refquota_tmp = request.form['refquota_tmp']
                encryption = request.form['encryption']  
                recordsize = request.form['recordsize']  
                # CONVERT INT TO BYTES
                try:
                    quota = int(quota_tmp) * 1073741824
                    refquota = int(refquota_tmp) * 1073741824                                                                     
                except ValueError:
                    flash("Quota must be an integer! (0 = no quota, 1 = 1GiB)",'danger')
                # DATASET CREATION
                try: 
                    ad_dataset(encryption,truenas_pool,home_dir,fullname,email,quota,refquota,recordsize,truenas_url,truenas_token)
                except Exception as e:
                    flash(e,'danger')
                # SAMBA SHARE CREATION    
                try:
                    hostsallow = request.form.getlist('hostsallow')                    
                    hostsdeny  = request.form.getlist('hostsdeny')           
                    ad_smb(hostsallow,hostsdeny,username,truenas_pool,home_dir,truenas_url,truenas_token)
                except Exception as e:
                    flash(e,'danger')
                # REBUILD AD CACHE FOR TrueNAS
                try:      
                    ad_cache(truenas_url,truenas_token)
                    sleep(3)    
                except Exception as e:                        
                    flash(e,'danger')
                # CALL THE SHARE ACL FUNCTION                                                                           
                try:
                    ad_acl(username,usergroup,truenas_url,truenas_pool,home_dir,truenas_token)                    
                    flash("Task ACL completed!",'success')                    
                except Exception as e:                        
                    flash(e,'danger')  
                # Getting the Encryption Key to store it in OnePassword
                try:
                    if encryption == 'YES':
                        diskkey = get_dataset_key(home_dir,truenas_pool,truenas_url,truenas_token)
                    else:
                        diskkey = 'NOT_ENCRYPTED'
                except Exception as e:                    
                    flash(e,'danger')     
                # Save to 1Password and shows the results
                try:                
                    data = app.config['DECRYPTED']        
                    data = json.loads(data)
                    onepwd_vault = data['onepwd_vault'] 
                    onepwd_token = data['onepwd_token'] 
                    # If we need to print the results
                    results = { 
                        "User": username,  
                        "Group": usergroup, 
                        "Fullname": fullname,     
                        "Email": email,              
                        "Shares": home_dir,
                        "Password": userpass,
                        "EncryptionKey": diskkey
                    }                     
                    diskkey = results['EncryptionKey']                    
                    onepassword_adsmb(username,usergroup,userpass,home_dir,email,fullname,diskkey,onepwd_token,onepwd_vault)                    
                    # CLEAN THE USER DATA
                    app.config['ADSMBUSERN'] = ''
                    app.config['ADSMBGROUP'] = ''
                    app.config['ADSMBUSPWD'] = ''
                    app.config['ADSMBFULNM'] = ''
                    app.config['ADSMBHOMED'] = ''
                    app.config['ADSMBEMAIL'] = ''
                    return render_template('results.html',spinner='addataset_data', results=results)
                except Exception as e:
                    flash(e,'danger')                             
    return render_template('addataset.html')       
########################################
@app.route('/addmodify', methods=('GET', 'POST'))
def admodify_data():
    ad_users = []     
    # VERIFY SESSION ID
    if not 'id' in session or app.config['DECRYPTED'] == []:
        return redirect(url_for('login'))           
    else:     
        # Get data from the config
        data = app.config['DECRYPTED']             
        try:
            # Get AD Users List
            ad_users = ldap_ulist(data)            
        except Exception as e:            
            flash(e,'danger')
        try:
            # Get AD Groups List         
            ad_groups = ldap_ugroup(data)
        except Exception as e:            
            flash(e,'danger')

        # AD MODIFY USER
        if 'adloadusermod' in request.args:             
            user = request.args.get('adloadusermod') # GET USER                         
            try:
                # GET USER INFO
                result = ldap_modifyuser(data,user)                     
                # FIX NASTED DICT
                entries = result['entries']                        
                admodres = ast.literal_eval(json.dumps(entries[0]))                 
                return admodres['attributes']
            except Exception as e:                    
                flash(e,'danger')                  
        # AD Remove User from Group
        if 'adloadusergroup' in request.args:                
            usersgroup = []
            adgroup = request.args.get('adloadusergroup') # GET GROUP                            
            try:
                result = ldap_listrmusergroup(data,adgroup)
                # TAKE THE MEMBERS FROM THE GROUP          
                entries = result['member']  
                # FILTER THE USERNAME (CN)
                for user in entries:
                    u = user.split(',', 1)[0]
                    u = u.split('CN=', 1)[1]                    
                    usersgroup.append(u)                    
                # entries = ast.literal_eval(json.dumps(entries))
                return usersgroup                                                   
            except Exception as e:                    
                flash(e,'danger')             
        # EXECUTION IF IS POSTING
        if request.method == 'POST':     
            
            # AD Modify User info
            if 'admodifyuser' in request.form:                  
                try:
                    # GET THE NEW USER INFO FROM THE FORM         
                    userold =  request.form['admodifyuser'] # GET OLD USERNAME  
                    username = request.form['username'] # GET NEW USERNAME   
                    firstname = request.form['firstname'] # GET FIRSTNAME   
                    lastname = request.form['lastname'] # GET LASTNAME
                    email = request.form['email'] # GET EMAIL   
                    # RUN THE CHANGES
                    result = ldap_modifyuserinfo(data,userold,username,firstname,lastname,email)          
                    if result.result['description'] != 'success':                    
                        flash('Problem with LDAP query','danger')
                    else:
                        flash('User Info Changed','success')
                except Exception as e:                    
                    flash(e,'danger')    

            # AD Rename Group Name
            if 'outputrenamegroupold' in request.args and 'outputrenamegroup' in request.args:                 
                adgroupold = request.args.get('outputrenamegroupold') # GET OLD GROUP NAME
                adgroupnew = request.args.get('outputrenamegroup') # GET NEW GROUP NAME                   
                try:
                    result = ldap_renamegroup(data,adgroupold,adgroupnew)                       
                    flash('Group Renamed','success')
                except Exception as e:                    
                    flash(e,'danger')  

            # AD PUT User to the Group
            if 'outputadaddusergroup' in request.form and 'outputadadduserg' in request.form:                 
                adusergroup = request.form.get('outputadadduserg') # GET GROUP                
                adgroup = request.form.get('outputadaddusergroup') # GET USER FROM GROUP                           
                try:
                    result = ldap_addusergroup(data,adgroup,adusergroup)   
                except Exception as e:                    
                    flash(e,'danger')    

            # AD Remove User from the Group
            if 'outputadermgroup' in request.form and 'outputadermusergroup' in request.form:                 
                adusergroup = request.form.get('outputadermusergroup') # GET GROUP                
                adgroup = request.form.get('outputadermgroup') # GET USER FROM GROUP           
                try:
                    result = ldap_rmusergroup(data,adgroup,adusergroup)   
                except Exception as e:                    
                    flash(e,'danger')    

            # AD Remove Group
            if 'outputaddeletegroup' in request.form:                
                adgroup = request.form.get('outputaddeletegroup') # GET GROUP                   )                   
                try:
                    result = ldap_rmgroup(data,adgroup)                                                                                                                 
                except Exception as e:                    
                    flash(e,'danger')               

            # AD USER RESET PASSWORD
            if 'outputadchangeuserpwd' in request.form:             
                user = request.form.get('outputadchangeuserpwd') # GET USER    
                aduserpwd = request.form['aduserpwd']      
                try:
                    ldap_uresetpwd(data,user,aduserpwd) 
                    result = "User "+user+" has a new Password: "+str(aduserpwd)                    
                    flash(result,'success')    
                    return redirect(url_for('admodify_data'))                     
                except Exception as e:                    
                    flash(e,'danger')    
            # AD ENABLE USER
            if 'outputadenableuser' in request.form:                
                user = request.form.get('outputadenableuser') # GET USER             
                try:
                    ldap_uenabledisable(data,user,512)  ### ENABLE LDAP USER
                    result = "User "+user+ " UNLOCKED!"
                    flash(result,'success')    
                    return redirect(url_for('admodify_data'))                     
                except Exception as e:                    
                    flash(e,'danger')    
            # AD DISABLE USER    
            if 'outputadedisableuser' in request.form:
                user = request.form.get('outputadedisableuser') # GET USER             
                try:
                    ldap_uenabledisable(data,user,514)  ### DISABLE LDAP USER
                    result = "User "+user+ " LOCKED!"
                    flash(result,'success')    
                    return redirect(url_for('admodify_data'))                     
                except Exception as e:                    
                    flash(e,'danger')       
            # AD DELETE USER    
            if 'outputadedeleteuser' in request.form:
                user = request.form.get('outputadedeleteuser') # GET USER      
                try:
                    ldap_udelete(data,user)  ### DELETE LDAP USER
                    result = "User "+user+ " DELETED!"
                    flash(result,'success')    
                    return redirect(url_for('admodify_data'))                     
                except Exception as e:                    
                    flash(e,'danger')                            
    
    return render_template('admodify.html',ad_users=ad_users,ad_groups=ad_groups)

###########################################
# TRUENAS iSCSI User,Target,Auth          #
###########################################
@app.route('/iscsi', methods=('GET', 'POST'))
def iscsi_data():
    if not 'id' in session or app.config['DECRYPTED'] == []:
        return redirect(url_for('login'))           
    else:          
        data = app.config['DECRYPTED']        
        data = json.loads(data)
        truenas_url = data['truenas_url'] 
        truenas_pool = data['truenas_pool']     
        truenas_token = data['truenas_token']   
        output = []    
        # GET FORM INFO
        if request.method == 'POST':      
            username = request.form['username']
            firstname = request.form['firstname']
            lastname = request.form['lastname']
            email = request.form['email']
            iscsi_disc_meth = request.form['iscsi_disc_meth']
            volsize_tmp = request.form['volsize_tmp']
            encryption = request.form['encryption']
            # Verify fields
            if not username or not firstname or not lastname or not email or not iscsi_disc_meth or not volsize_tmp or not encryption:
                flash('Please fill all required fields!','warning')
            else:                
                # Convert ZVOL Size
                try:                
                    volsize_tmp = int(volsize_tmp)                
                    volsize = int(volsize_tmp*1073741824)  
                except Exception as e:
                    flash('Please fill an Integer value 1 = 1Gib!','warning')
                    flash(e,'warning')
                # Email validation
                if check_email_address(email) != True:
                    output = check_email_address(email)
                    flash(output,'danger')
                else:              
                    try:
                        # Generating values and secrets
                        usergroup = username
                        username = username+'-'+secrets.token_hex(3) # secrets.token_urlsafe(30*3//4) # see notes
                        fullname = firstname+' '+lastname    
                        home_dir = usergroup+'-'+str(uuid.uuid4())  
                        # CHECKING IF CHAP/MUTUAL CHAP
                        if iscsi_disc_meth != "NONE":  
                            peeruser = usergroup+'-'+secrets.token_hex(3) # secrets.token_urlsafe(30*3//4) # see notes                        
                            userpass = password_generator(16,'') 
                            peersecret = password_generator(16,'')  
                        else:
                            userpass = password_generator(16,'') 
                            peeruser = ""
                            peersecret = ""
                        # CREATE ZVOL
                        data_json = truenas_iscsi_zvol(encryption,truenas_pool,home_dir,volsize,truenas_url,truenas_token,username,userpass,peeruser,peersecret)                         
                        user_json = json.loads(data_json)   
                        # Forward arguments via app.config instead url POST
                        app.config['ISCSIUSER'] = username                        
                        app.config['ISCSI_DISC_METH'] = iscsi_disc_meth                         
                        app.config['USER_JSON'] = str(user_json)
                        app.config['ISCSIFULLN'] = fullname
                        app.config['ISCSIEMAIL'] = email
                        app.config['ISCSIHOMED'] = home_dir
                        app.config['ISCSIGROUP'] = usergroup
                        app.config['ISCSIENCRY'] = encryption     
                        app.config['ISCSIGROUPID'] = str(user_json['tag'])
                        return redirect(url_for('itarget_data'))                                 
                    except Exception as e:                         
                        flash(e,'danger')
                        return render_template('iscsi.html')
    return render_template('iscsi.html')
########################################
@app.route('/itarget', methods=('GET', 'POST'))
def itarget_data():    
    if not 'id' in session or app.config['DECRYPTED'] == []:
        return redirect(url_for('login'))           
    else:          
        data = app.config['DECRYPTED']        
        data = json.loads(data)
        truenas_url = data['truenas_url'] 
        truenas_pool = data['truenas_pool']    
        truenas_token = data['truenas_token']                
        tn_list = [{'id':'new'}] # Target List    
        # SHOW TARGETS LIST
        try: 
            r = r_get(truenas_url,'/api/v2.0/iscsi/target',truenas_token)
            data_target = r.json()                  
            for t_name in data_target:                
                tn_list.append(t_name)
        except Exception as e:
            flash(e,'danger')    
        # POSTING NEW TARGET
        if request.method == 'POST':        
            # GET INFO FORM
            blockname = request.form['blockname'].lower().strip()        
            extenttype = request.form['extenttype']
            target_id = request.form['target']     
            # GET INFO FROM PASSED APP CONFIG MAP
            username = app.config['ISCSIUSER']
            home_dir =  app.config['ISCSIHOMED']
            user_json = app.config['USER_JSON']            
            encryption = app.config['ISCSIENCRY']
            fullname = app.config['ISCSIFULLN']
            usergroup = app.config['ISCSIGROUP']  
            groupid = app.config['ISCSIGROUPID']  
            email = app.config['ISCSIEMAIL']         
            app.config['ISCSIBLKNM'] = blockname
            comment = username," Customer Target"
            #
            if not blockname or not extenttype or not target_id or not username or not home_dir:
                flash('Please fill all required fields!','warning')
            else: 
                # CHECK IF USED PREVIOUS TARGET
                if target_id != 'new':
                    target = int(target_id)
                    for id_tn in tn_list:                
                        if id_tn['id'] == target:
                            target = id_tn                                    
                # COPY ALL CONFIG FROM THE SELECTED TARGET (LIST)
                    try:
                        auth_networks_ip = target['auth_networks']
                        data_groups = target['groups'][0]                                                                        
                        iscsi_initiator = data_groups['initiator']                                                
                        iscsi_portal = data_groups['portal']
                        iscsi_meth = data_groups['auth']                        
                        iscsi_disc_meth = data_groups['authmethod']
                        truenas_iscsi_target(blockname,comment,iscsi_initiator,auth_networks_ip,iscsi_portal,iscsi_meth,iscsi_disc_meth,truenas_url,truenas_token)                                                       
                    except Exception as e:
                        flash(e,'danger')                    
                # MAKES THE EXTENT
                    try:                
                        results = truenas_iscsi_extent(blockname,username,target_id,extenttype,truenas_pool,home_dir,truenas_url,truenas_token)     
                        # SANITAZE RESULTS
                        results = json.loads((results))
                        # SANITAZE RESULTS        
                        user_json = user_json.replace("\'", "\"")
                        user_json = json.loads(user_json)                                                                                             
                        # MERGE RESULTS
                        results = {**results, **user_json}                                                
                    except Exception as e:                                  
                        flash(e,'danger')                
                    # STORE PASSWORD TO 1PASSWORD IF POSITIVE RESULTS                    
                    try:
                        data = app.config['DECRYPTED']        
                        data = json.loads(data)
                        onepwd_vault = data['onepwd_vault'] 
                        onepwd_token = data['onepwd_token'] 
                        # Getting the Encryption Key to store it in OnePassword
                        try:
                            if encryption == 'YES':
                                diskkey = get_dataset_key(home_dir,truenas_pool,truenas_url,truenas_token)
                            else:
                                diskkey = 'NOT_ENCRYPTED'
                        except Exception as e:                    
                            flash(e,'danger')
                        
                        userpass = user_json['secret']    
                        if not "peeruser" in user_json and not "peersecret" in user_json:                       
                            peeruser = "NONE"
                            peersecret = "NONE"                        
                        else:
                            peeruser = user_json['peeruser']
                            peersecret = user_json['peersecret']                             
                        # Save to 1Password and shows the results
                        onepassword_iscsi(username,str(usergroup),str(userpass),str(peeruser),str(peersecret),blockname,home_dir,email,fullname,diskkey,onepwd_token,onepwd_vault)                                
                        return render_template('results.html',results=results) 
                    except Exception as e:                                           
                        flash(e,'danger')     
                ##############################                                                
                # REDIRECT TO CREATE NEW TARGET
                else:                        
                    return redirect(url_for('iinitiator_data'))                       
    return render_template('itarget.html',tn_list=tn_list)        
########################################
@app.route('/iinitiator', methods=('GET', 'POST'))
def iinitiator_data():   
    if not 'id' in session or app.config['DECRYPTED'] == []:
        return redirect(url_for('login'))           
    else:   
        # GET ARGS FROM APP CONFIG
        username = app.config['ISCSIUSER']
        home_dir =  app.config['ISCSIHOMED']
        user_json =  app.config['USER_JSON']
        encryption = app.config['ISCSIENCRY']
        fullname = app.config['ISCSIFULLN']
        usergroup = app.config['ISCSIGROUP']  
        iscsi_disc_meth = app.config['ISCSI_DISC_METH'] 
        email = app.config['ISCSIEMAIL']   
        groupid = app.config['ISCSIGROUPID']            
        blockname = app.config['ISCSIBLKNM']
        # GET CONFIG FROM FILE              
        data = app.config['DECRYPTED']        
        data = json.loads(data)
        truenas_url = data['truenas_url'] 
        truenas_pool = data['truenas_pool']                 
        truenas_token = data['truenas_token']   
        pn_list = [] # Portal List    
        in_list = [] # Initiator List
        # SHOW THE PORTARLS LIST
        try:        
            r = r_get(truenas_url,'/api/v2.0/iscsi/portal',truenas_token)                       
            data_portal = r.json()            
            for p_name in data_portal:            
                pn_list.append(p_name)
        except Exception as e:            
            flash(e,'danger')    
        # List of initiator
        try:
            r = r_get(truenas_url,'/api/v2.0/iscsi/initiator',truenas_token)                         
            data_initiator = r.json()   
            init_list_text = 'Select it from the list or press + for a new one'     
            in_list = [init_list_text] # Init a New Initiator List  
            for i_name in data_initiator:                                      
                in_list.append(i_name)       
        except Exception as e:            
            flash(e,'danger')  
        # POSTING THE FORM DATA      
        if request.method == 'POST':              
            # GET INFO FROM FORM
            iscsi_portal = request.form['iscsi_portal']
            auth_networks = request.form.getlist('auth_networks')
            iscsi_initiator = request.form['iscsi_initiator']             
            item_iqn_initiator = request.form.getlist('niscsi_initiator')
            add_cliqn_initiator = request.form['add_cliqn_initiator']              
            # CHECK IF IS A NEW INITIATOR
            try:
                if iscsi_initiator == init_list_text:                    
                    # VERIFY AUTH NETWORKS IP
                    for aip in auth_networks:
                        try:                    
                            validate_ip(aip)
                        except Exception as e:
                            flash(e,'danger')
            except Exception as e:                
                flash(e,'danger')                              
            # CREATE THE INITIATOR 
            try:
                results = truenas_iscsi_init(iscsi_initiator,item_iqn_initiator,add_cliqn_initiator,iscsi_portal,truenas_url,truenas_token,blockname,auth_networks,groupid,iscsi_disc_meth)                
            except Exception as e:                
                flash(e,'danger')                
            try:
                # GET ARGS
                data = app.config['DECRYPTED']        
                data = json.loads(data) 
                onepwd_vault = data['onepwd_vault'] 
                onepwd_token = data['onepwd_token']                          
                # SANITAZE RESULTS        
                user_json = user_json.replace("\'", "\"")
                user_json = json.loads(user_json)                
                userpass = user_json['secret']  
                if not "peeruser" in user_json and not "peersecret" in user_json:                       
                    peeruser = "NONE"
                    peersecret = "NONE"                        
                else:
                    peeruser = user_json['peeruser']
                    peersecret = user_json['peersecret']                                                                      
                # MERGE RESULTS            
                results = {**results, **user_json} 
            # CHECK ENCRYPTION
                if encryption == 'YES':
                    diskkey = get_dataset_key(home_dir,truenas_pool,truenas_url,truenas_token)
                else:
                    diskkey = 'NOT_ENCRYPTED'
            except Exception as e:                           
                flash(e,'danger') 
            try: 
                onepassword_iscsi(username,str(usergroup),str(userpass),str(peeruser),str(peersecret),blockname,home_dir,email,fullname,diskkey,onepwd_token,onepwd_vault)                    
                # onepassword_iscsi(username,usergroup,userpass,peeruser,peersecret,blockname,home_dir,email,fullname,diskkey,onepwd_token,onepwd_vault)                                                                                                                    
                return render_template('results.html',spinner='initiator', results=results)                                                                   
            except Exception as e:                               
                flash(e,'danger')                                   
    return render_template('iinitiator.html',pn_list=pn_list,in_list=in_list)  
######################################## PRINT SCRIPT CURRENT CONFIG
@app.route("/settings", methods=('GET', 'POST'))
def settings():  
    if not 'id' in session or app.config['DECRYPTED'] == []:
        return redirect(url_for('login'))           
    else:      
        # READ CONFIG FILE           
        data = app.config['DECRYPTED']               
        data = json.loads(data)
        truenas_url = data['truenas_url'] 
        truenas_pool = data['truenas_pool']        
        ldap_url = data['ldap_url']
        ldap_u_cn = data['ldap_u_cn']
        ldap_g_cn = data['ldap_g_cn']
        ldap_admin = data['ldap_admin']
        ldap_pwd = data['ldap_pwd']        
        domain = data['domain']
        onepwd_url = data['onepwd_url']
        onepwd_vault = data['onepwd_vault']
        truenas_token = data['truenas_token']
        onepwd_token = data['onepwd_token']  
        # SAVE FILE
        if request.method == 'POST':                    
            truenas_url = request.form['truenas_url']       
            truenas_pool = request.form['truenas_pool']
            ldap_url = request.form['ldap_url']
            ldap_u_cn = request.form['ldap_u_cn']
            ldap_g_cn = request.form['ldap_g_cn']  
            ldap_admin = data['ldap_admin']
            ldap_pwd = data['ldap_pwd']         
            domain = request.form['domain']
            onepwd_url = request.form['onepwd_url']
            onepwd_vault = request.form['onepwd_vault']
            truenas_token = request.form['truenas_token']
            onepwd_token = request.form['onepwd_token'] 
            userkey = request.form['userkey']
            if not truenas_url or not truenas_pool or not ldap_url or not ldap_u_cn or not ldap_g_cn or not ldap_admin or not ldap_pwd or not domain or not onepwd_url or not onepwd_vault or not truenas_token or not onepwd_token or not userkey:
                flash('Please fill all required fields!','warning')
            else:
                try:
                    data = {                
                        "truenas_url": truenas_url,
                        "truenas_pool": truenas_pool,
                        "ldap_url": ldap_url,
                        "ldap_u_cn": ldap_u_cn,
                        "ldap_g_cn": ldap_g_cn,
                        "ldap_admin": ldap_admin,
                        "ldap_pwd": ldap_pwd,
                        "domain": domain,
                        "onepwd_url": onepwd_url,
                        "onepwd_vault": onepwd_vault,
                        "onepwd_token": onepwd_token,
                        "truenas_token": truenas_token
                    }                     
                    data = json.dumps(data)
                    data = bytes(str(data), 'utf-8')                                        
                    fernet = Fernet(userkey)      
                    encrypted = fernet.encrypt(data)
                    with open(app.config['CONFIG_FOLDER']+'truenasdb', 'wb') as dec_file:
                            dec_file.write(encrypted)
                            dec_file.close()    
                    flash("Configuration Saved",'success')
                except Exception as e:
                    flash(e,'danger')
    return render_template('settings.html',truenas_url=truenas_url,truenas_pool=truenas_pool,ldap_url=ldap_url,ldap_u_cn=ldap_u_cn,ldap_g_cn=ldap_g_cn,ldap_admin=ldap_admin,ldap_pwd=ldap_pwd,domain=domain,onepwd_url=onepwd_url,truenas_token=truenas_token,onepwd_token=onepwd_token,onepwd_vault=onepwd_vault)
########################################
#  USER PROFILE, CHANGE PASSWORD KEY   #
########################################
@app.route("/profile", methods=('GET', 'POST'))
def user_profile():  
    if not 'id' in session or app.config['DECRYPTED'] == []:
        return redirect(url_for('login'))           
    else:     
        if request.method == 'POST':
            if not request.form['userkey']:            
                flash('Insert the Password Key.','warning')
            else: # Decrypt config file base on the password key
                try:
                    fernet = Fernet(request.form['userkey'])                                       
                    with open(app.config['CONFIG_FOLDER']+'truenasdb', 'rb') as enc_file:
                        encrypted = enc_file.read()                
                        decrypted = fernet.decrypt(encrypted)      
                        enc_file.close()                          
                except Exception as e:
                    flash('Insert the old Password Key.','danger')  
                    flash(e)
                # GENERATE NEW KEY AND ENC
                try:                                          
                    # Generate the new password key
                    key = Fernet.generate_key()                    
                    fernet = Fernet(key)                        
                    encrypted = fernet.encrypt(decrypted)
                    # Store new encrypted file
                    with open(app.config['CONFIG_FOLDER']+'truenasdb', 'wb') as dec_file:
                        dec_file.write(encrypted)
                        dec_file.close()
                    flash("New Password Key: "+(key.decode("utf-8")),'success')        
                    session.pop('id', None) # remove session id for logout
                except Exception as e:
                    flash('Something wrong with the encryption.','danger')      
                    flash(e,'danger')          
    return render_template('profile.html')         
########################################
if __name__ == "__main__":
    # app.run(host='0.0.0.0', port=443, ssl_context='adhoc', ssl_context=('cert.pem', 'key.pem'))
    app.run(host='0.0.0.0', port=8443, ssl_context='adhoc')
    # app.run(host='0.0.0.0', port=80, debug=True, use_reloader=True)   