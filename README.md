# truenas_ldap_flask_tools
A webtool in Python Flask that creates a LDAP user and his TrueNAS shares pool in ISCSI or NFS.

1. There is a sperimental part that store the above user info, directly to onepassword.
2. The configuration file is encrypted with the master key.
3. Is using the python LDAP3 libraries.
4. Using the TrueNAS scale API.

Before you start install python3 and his libraries with:

- pip3 install -r requirements.txt 
or for docker:
- docker build -t truenastools .

Run the script with:

- WEB = python3 app.py
- DOCKER = docker run -it -p 8443:8443 -d truenastools
- Browser = https://x.x.x.x:8443/login
- Login = default key is "xj2wqXEdYsVGnb3ISAD4Ok3velzBNS7K3AHj7aTvQVw=" PLEASE CHANGE IT

The WEB version (beta) script is handling 2 main tasks:

- The first part is focusing on LDAP/AD connection, there are many frameworks for that, and this script is using the python LDAPv3 libraries.
- The second part is using a normal API HTTPS (GET/POST) request, to manage TrueNas and (the 1Password API).

Active Directory Creation steps:

1. Create User and Group
2. Create shares, encrypt, quota
3. Credentials to 1Password

Active Directory Modify steps:

1. Modify User Info
2. Reset User Password
3. Enabled User
4. Disable User
5. Delete User
6. Add user to Group
7. Remove User from Group
8. Rename Group name
9. Delete Group

---

iSCSI Creation Steps:
1. Create User
2. Create ZVOL
3. Auth Meth (NONE,CHAP,MUTUAL_CHAP)
4. Create Target
5. Create Initiatior if new
7. Use existing Target with Portal

---

LDAP Users and Groups syntax:

- User = CustomerID + HEX#3 = u12345-hex#3)
- Group = CustomerID only (u12345)
- Password = Complex, 12 characters

**LDAPv3 Docs:** <https://ldap3.readthedocs.io/en/latest/>

**TrueNas Docs:** <https://labsan01.wscloud.lab/api/docs/> (for the LAB)

**1Password Docs:** <https://developer.1password.com/docs/connect/connect-api-reference/>
