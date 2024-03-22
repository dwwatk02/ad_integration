#!/usr/bin/env python3

from tempfile import NamedTemporaryFile
from ldap3 import Server, Connection, ALL, NTLM, SUBTREE
import requests
import json
import csv
import shutil
import os
#from extract import json_extract

"""
This class should contain wrapper functions around the ASOC API
It can currently login, logout, and run a dast scan.
Each function returns a tuple of the HTTP status code (200,201,401,403, etc...) and result (usually json)
"""
class ASoC:
    auth_token = None
    keyId = None
    keySecret = None
    debug = False
    session = None
    verifyCerts = None
    ldap_cred = {'server_ip': '127.0.0.1','user': 'domain\\user','password': ''}

    ldap_conn = Connection(Server(ldap_cred['server_ip']),user=ldap_cred['user'],password=ldap_cred['password'],authentication=NTLM,auto_bind=True)

    ldap_users_dir = 'CN=Users,DC=EC2AMAZ,DC=local'
    ldap_servers_dir = 'CN=Users,DC=EC2AMAZ,DC=local'
    user_group = 'Mobile'

    
    def __init__(self, keyId, keySecret):
        self.keyId = keyId
        self.keySecret = keySecret
        self.session = requests.Session()
        self.session.verify = False
    def get_group(group_name):
        ldap_conn.search(ldap_servers_dir, '(cn={})'.format(group_name))
        return ldap_conn.response[0]['dn']

    def get_users(group_path):
        ldap_conn.search(ldap_users_dir,'(&(cn=*)(memberOf={})(objectClass=User)(!(userAccountControl=514))(!(userAccountControl=66050)))'.format(group_path),attributes=('sAMAccountName', 'memberof','mail'),search_scope=SUBTREE)
        return ldap_conn.entries
        
    def getADUser(self,group):
        ldap_cred = {'server_ip': '192.168.69.119','user': 'EC2AMAZ.local\\appscanadmin','password': 'd@tchf1re@ppscan'}

        ldap_conn = Connection(Server(ldap_cred['server_ip']),user=ldap_cred['user'],password=ldap_cred['password'],authentication=NTLM,auto_bind=True)

        ldap_users_dir = 'CN=Users,DC=EC2AMAZ,DC=local'
        ldap_servers_dir = 'CN=Users,DC=EC2AMAZ,DC=local'
        user_group = group
        ldap_conn.search(ldap_servers_dir, '(cn={})'.format(user_group))
        group_p = ldap_conn.response[0]['dn']
        ldap_conn.search(ldap_users_dir,'(&(cn=*)(memberOf={})(objectClass=User)(!(userAccountControl=514))(!(userAccountControl=66050)))'.format(group_p),attributes=('sAMAccountName', 'memberof','mail'),search_scope=SUBTREE)
        users = ldap_conn.entries
        user_object = []
        for user in users:
            user_n = user.sAMAccountName.value.lower()
            user_mail = user.mail.value.lower()
            #print(user.memberof.value)
            user_object.append(user_mail)

        return user_object

    def doesUserExist(self,userID):
        req = requests.Request("GET", \
            'https://cloud.appscan.com/api/v4/User?filter=Username%20eq%20%27'+userID+'%27', \
            headers=self.session.headers)
        preparedRequest = req.prepare()
        r = self.session.send(preparedRequest)
        if r.status_code == 200:
            return r.json()
            
    def isUserInAssetGroup(self,userID,group):
        req = requests.Request("GET", \
            'https://cloud.appscan.com/api/v4/User?%24filter=Username%20eq%20%27'+userID+'%27%20and%20%28%28AssetGroups%2Fany%28item%3A%20item%2FName%20eq%20%27'+group+'%27%29%29%29&%24expand=AssetGroups', \
            headers=self.session.headers)
        preparedRequest = req.prepare()
        r = self.session.send(preparedRequest)
        if r.status_code == 200:
            return r.json()
            
    def getUsersInAssetGroup(self,group):
        req = requests.Request("GET", \
            'https://cloud.appscan.com/api/v4/User?%24filter=AssetGroups%2Fany%28d%3Ad%2FName%20eq%20%27'+group+'%27%29&%24select=UserName', \
            headers=self.session.headers)
        preparedRequest = req.prepare()
        r = self.session.send(preparedRequest)
        if r.status_code == 200:
            user_list = []
            user_return = r.json()['Items']
            for user in user_return:
                user_list.append(user['UserName'])
                
            return user_list
        else:
            print("Error getting users in Asset Group: "+group+".  API call return: "+r.text)
            
    def login(self):
        data={
          "KeyId": self.keyId,
          "KeySecret": self.keySecret
        }
        additionalHeaders = { 
            "Content-Type": "application/json",
            "Accept":"application/json"
        }
        self.session.headers.update(additionalHeaders)
        req = requests.Request("POST", \
            "https://cloud.appscan.com/api/v4/Account/ApiKeyLogin", \
            headers=self.session.headers, \
            data=json.dumps(data))
        preparedRequest = req.prepare()
        r = self.session.send(preparedRequest)
            
        if r.status_code == 200:
            result = r.json()
            self.auth_token = result["Token"]
            self.session.headers.update({"Authorization": "Bearer " + self.auth_token})
            return r.status_code, r.text
        else:
            return r.status_code, r.text

    def logout(self):
        req = requests.Request("GET", \
            "https://cloud.appscan.com/api/V4/Account/Logout", \
            headers=self.session.headers)
        preparedRequest = req.prepare()
        r = self.session.send(preparedRequest)
        if r.status_code == 200:
            self.authToken = None
        return r.status_code, r.text
        
    def getAllAssetGroups(self):
        req = requests.Request("GET", \
            'https://cloud.appscan.com/api/v4/AssetGroups?select=Name', \
            headers=self.session.headers)
        preparedRequest = req.prepare()
        r = self.session.send(preparedRequest)
        if r.status_code == 200:
            return r.json()
        #return r.status_code, r.text
        
    def getAssetGroupByName(self,name):
        req = requests.Request("GET", \
            'https://cloud.appscan.com/api/v4/AssetGroups?filter=Name%20eq%20%27'+name+'%27&%24select=Id', \
            headers=self.session.headers)
        preparedRequest = req.prepare()
        r = self.session.send(preparedRequest)
        if r.status_code == 200:
            return r.json()
        #return r.status_code, r.text

    def deleteAssetGroup(self,asset_group_id):
        print("in")
        req = requests.Request("DELETE", \
            'https://cloud.appscan.com/api/v4/AssetGroups/'+asset_group_id, \
            headers=self.session.headers)
        preparedRequest = req.prepare()
        r = self.session.send(preparedRequest)
        if r.status_code == 204:
            return r.json()
        else:
            print(r.status_code)
            
        #return r.status_code, r.text

    def updateUserAssetGroups(self,uid,asset_groups):
        data={"AssetGroupIds":asset_groups}
        req = requests.Request("PUT", 'https://cloud.appscan.com/api/v4/User/'+uid, headers=self.session.headers, data=json.dumps(data))
        preparedRequest = req.prepare()
        r = self.session.send(preparedRequest)
        if r.status_code == 200:
            #print(uid + " added to Asset Groups: " + str(asset_groups))
            result = r.json()
        else:
            print(r.status_code)
            print(uid+" user update failed")

    def createAssetGroup(self,admin_uid,group_name):
        data={ 
          "ContactUserId": admin_uid,
          "Name": group_name,
          "Description": ""
        }
        req = requests.Request("POST", 'https://cloud.appscan.com/api/v4/AssetGroups', headers=self.session.headers, data=json.dumps(data))
        preparedRequest = req.prepare()
        r = self.session.send(preparedRequest)
        if r.status_code == 201:
            result = r.json()
            #print(group_name + " successfully created in ASoC")
            return result
        else:
            print("Error creating Asset Group "+r.status_code)
            

    def checkAuth(self):
        headers = {
            "Accept": "application/json",
            "Authorization": "Bearer "+self.auth_token
        }
        resp = requests.get("https://cloud.appscan.com/api/V2/Account/TenantInfo", headers=headers)
        return resp.status_code == 200


    def getUsers(self):
        headers = {
            "Accept": "application/json",
            "Authorization": "Bearer "+self.auth_token
        }

        resp = requests.get("https://cloud.appscan.com/api/V2/Users", headers=headers)
        
        if(resp.status_code == 200):

            return resp.json()
        else:
            #logger.debug("ASoC App Summary Error Response")
            #self.logResponse(resp)
            print("error")
            return None





    def inviteUsers(self,email_list,asset_group_id,role_id):
        headers = {
            "Accept": "application/json",
            "Authorization": "Bearer "+self.auth_token
        }
        data={}
        email_dict = []
        email_dict.append(email_list)
        data["Emails"]=email_dict
        #asset_group_dict = []
        #asset_group_dict.append(asset_group_id)
        data["AssetGroupIds"] = asset_group_id
        data["RoleId"] = role_id
        resp = requests.post("https://cloud.appscan.com/api/v4/Account/InviteUsers",headers=headers,json=data)
        if(resp.status_code==200):
            #print(email_list + " successfully added to ASoC")
            return True
        else:
            print(resp.status_code)
            return False


