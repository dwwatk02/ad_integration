#!/usr/bin/env python3

from ldap3 import Server, Connection, NTLM, SUBTREE
import requests
import json
import urllib3


urllib3.disable_warnings()


# ==================================================
# Configuration
# ==================================================

# AD Configuration

LDAP_SERVER = ""
LDAP_USER = "domain\\user"
LDAP_PASSWORD = ""

BASE_DN = ""


# ASoC Configuration

ASOC_KEY_ID = ""
ASOC_KEY_SECRET = ""

ASOC_ADMIN_UID = ""
# Default role/profile under which a new user will be added
ASOC_ROLE_UID = ""


# ==================================================
# LDAP Functions
# ==================================================

def connect_ldap():

    server = Server(LDAP_SERVER)

    conn = Connection(
        server,
        user=LDAP_USER,
        password=LDAP_PASSWORD,
        authentication=NTLM,
        auto_bind=True
    )

    return conn



def get_daa_groups(conn):

    conn.search(
        BASE_DN,
        "(&(objectClass=group)(cn=DAA_*))",
        attributes=[
            "cn",
            "distinguishedName"
        ],
        search_scope=SUBTREE
    )

    return conn.entries



def get_group_members(conn, group_dn):

    members=[]

    conn.search(
        BASE_DN,
        f"(&(objectClass=user)(memberOf:1.2.840.113556.1.4.1941:={group_dn}))",
        attributes=[
            "mail",
            "sAMAccountName",
            "distinguishedName"
        ],
        search_scope=SUBTREE
    )


    for user in conn.entries:

        # Prefer email for ASoC usernames
        if user.mail.value:

            members.append(
                user.mail.value.lower()
            )

        else:

            members.append(
                user.sAMAccountName.value.lower()
            )


    return members



# ==================================================
# ASoC API Class
# ==================================================

class ASoC:


    def __init__(self,key,secret):

        self.key=key
        self.secret=secret

        self.session=requests.Session()

        self.session.verify=False



    def login(self):

        data={
            "KeyId":self.key,
            "KeySecret":self.secret
        }


        r=self.session.post(
            "https://cloud.appscan.com/api/v4/Account/ApiKeyLogin",
            json=data
        )


        if r.status_code == 200:

            token=r.json()["Token"]

            self.session.headers.update(
                {
                    "Authorization":
                    "Bearer "+token
                }
            )

            print("ASoC Login successful")

        else:

            raise Exception(
                "ASoC Login failed"
            )



    def get_asset_group(self,name):

        r=self.session.get(
            "https://cloud.appscan.com/api/v4/AssetGroups",
            params={
                "filter":
                f"Name eq '{name}'"
            }
        )


        return r.json()["Items"]



    def create_asset_group(self,name):

        data={
            "ContactUserId":ASOC_ADMIN_UID,
            "Name":name,
            "Description":"Created from AD synchronization"
        }


        r=self.session.post(
            "https://cloud.appscan.com/api/v4/AssetGroups",
            json=data
        )


        if r.status_code == 201:

            print(
                f"Created Asset Group {name}"
            )



    def get_users_in_asset_group(self,name):

        r=self.session.get(
            "https://cloud.appscan.com/api/v4/User",
            params={
                "$filter":
                f"AssetGroups/any(x:x/Name eq '{name}')",
                "$select":
                "UserName"
            }
        )


        users=[]

        for user in r.json()["Items"]:

            users.append(
                user["UserName"].lower()
            )


        return users



    def find_user(self,email):

        r=self.session.get(
            "https://cloud.appscan.com/api/v4/User",
            params={
                "filter":
                f"Username eq '{email}'"
            }
        )

        return r.json()["Items"]



    def update_user_groups(self,user_id,groups):

        data={
            "AssetGroupIds":groups
        }


        self.session.put(
            f"https://cloud.appscan.com/api/v4/User/{user_id}",
            json=data
        )
        
    def remove_user_from_asset_group(self, username, asset_group_name):

        print(
            f"Removing {username} from Asset Group {asset_group_name}"
        )


        # Find user
        r = self.session.get(
            "https://cloud.appscan.com/api/v4/User",
            params={
                "filter": f"Username eq '{username}'",
                "$expand": "AssetGroups"
            }
        )


        if r.status_code != 200:

            print(
                f"Failed finding user {username}"
            )

            return False


        users = r.json()["Items"]


        if not users:

            print(
                f"User {username} does not exist in ASoC"
            )

            return False



        user = users[0]

        user_id = user["Id"]


        current_groups = user.get(
            "AssetGroups",
            []
        )


        new_group_ids = []


        removed = False


        for group in current_groups:


            if group["Name"].lower() == asset_group_name.lower():

                print(
                    f"Removing membership from {group['Name']}"
                )

                removed = True

            else:

                new_group_ids.append(
                    group["Id"]
                )



        if removed:


            self.update_user_groups(
                user_id,
                new_group_ids
            )


            print(
                f"{username} updated. Remaining groups: {new_group_ids}"
            )


        else:

            print(
                f"{username} was not a member of {asset_group_name}"
            )


        return True    



    def get_asset_group_id(self,name):

        result=self.get_asset_group(name)

        if result:

            return result[0]["Id"]

        return None



    def invite_user(self,email,group_id):

        data={

            "Emails":[email],

            "AssetGroupIds":[group_id],

            "RoleId":ASOC_ROLE_UID

        }


        r=self.session.post(

            "https://cloud.appscan.com/api/v4/Account/InviteUsers",

            json=data

        )


        if r.status_code==200:

            print(
                f"Invited {email}"
            )



# ==================================================
# Synchronization Logic
# ==================================================

def synchronize(asoc,ldap):


    groups=get_daa_groups(ldap)


    print(
        f"Found {len(groups)} DAA groups"
    )


    for ad_group in groups:


        ad_name=ad_group.cn.value


        asoc_name=ad_name.replace(
            "DAA_",
            "",
            1
        )


        print("\nProcessing:")
        print(ad_name)
        print("ASoC Group:")
        print(asoc_name)



        # Create Asset Group if missing

        existing=asoc.get_asset_group(
            asoc_name
        )


        if not existing:

            asoc.create_asset_group(
                asoc_name
            )


        group_id=asoc.get_asset_group_id(
            asoc_name
        )



        # AD users

        ad_users=get_group_members(
            ldap,
            ad_group.distinguishedName.value
        )


        print(
            "AD Members:",
            ad_users
        )



        asoc_users=asoc.get_users_in_asset_group(
            asoc_name
        )


        print(
            "ASoC Members:",
            asoc_users
        )



        # Add missing users

        for user in ad_users:


            if user not in asoc_users:


                result=asoc.find_user(user)


                if result:

                    print(
                        f"Adding {user}"
                    )

                    # user already exists
                    # add group membership here

                else:

                    asoc.invite_user(
                        user,
                        group_id
                    )



        # Remove users

        for user in asoc_users:


            if user not in ad_users:

                asoc.remove_user_from_asset_group(user,asoc_name)



# ==================================================
# Main
# ==================================================

ldap=connect_ldap()


asoc=ASoC(
    ASOC_KEY_ID,
    ASOC_KEY_SECRET
)


asoc.login()


synchronize(
    asoc,
    ldap
)


print("\nSynchronization complete")
