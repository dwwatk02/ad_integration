#!/usr/bin/python3

from asoc_api import ASoC
import urllib3


urllib3.disable_warnings()

## Set variables (API Key and Secret, admin UID, and role UID)
keyId=""
keySecret=""
AD_group_file="AD_groups.txt"
admin_uid=""
role_uid = ""

asoc = ASoC(keyId, keySecret)
asoc.logger("---Starting script execution---")
code, result = asoc.login()
if code != 200:
    print(f'error logging into ASOC!! code is {code}')

## Get all Asset Groups and put into list to compare with what is in AD group file (source of truth)
all_asset_groups = asoc.getAllAssetGroups()['Items']
all_asset_group_list = []
for asset_groups in all_asset_groups:
    if asset_groups['Name'] != 'DEFAULT_ASSET_GROUP':
        all_asset_group_list.append(asset_groups['Name'])

all_groups_list = []
## Loop through AD group file
with open(AD_group_file) as f:
    all_groups_list = f.read().splitlines()
    for group in all_groups_list:
        result = asoc.getAssetGroupByName(group)
        if result['Items']:
            asoc.logger("Asset group "+group+" exists in ASoC.")
        else:
            asoc.logger("Asset group "+group+" does NOT exist in ASoC.  Creating now.")
            asoc.createAssetGroup(admin_uid,group)

## Find if group exists in ASoC but not in AD group file.  If any do exist, delete from ASoC
diff_asset_group_list = [item for item in all_asset_group_list if item not in all_groups_list]
for asset_group in diff_asset_group_list:
    asset_group_id = asoc.getAssetGroupByName(asset_group)['Items'][0]['Id']
    asoc.deleteAssetGroup(asset_group_id)
    asoc.logger("Asset Group: "+asset_group+" deleted")

with open(AD_group_file) as f:
    all_groups = f.read().splitlines()
    for group in all_groups:
        ## Get users in AD group and users in corresponding ASoC Asset Group
        AD_users = asoc.getADUser(group)
        asoc_users = asoc.getUsersInAssetGroup(group)
        ## Find list of users in Asset Group but not in AD (user needs to be removed from Asset Group)
        diff_user_list = [item for item in asoc_users if item not in AD_users]
        for diff_user in diff_user_list:
            asoc.logger("Deleting user " + diff_user + " from Asset Group "+ group)
            user_result = asoc.doesUserExist(diff_user)
            uid = user_result['Items'][0]['Id']
            user_asset_groups = user_result['Items'][0]['AssetGroups']
            asset_group_ids = []
            for asset_group in user_asset_groups:
                if asset_group['Name'] != group:
                    asset_group_ids.append(asset_group['Id'])
            asoc.updateUserAssetGroups(uid,asset_group_ids)
            asoc.logger("Updating user "+ diff_user + " with asset_group_ids: " + str(asset_group_ids))

        if AD_users:
            for user in AD_users:
                result = asoc.doesUserExist(user)
                if result['Items']:
                    asoc.logger(user+" user exists in ASoC")
                    uid = result['Items'][0]['Id']
                    user_asset_groups = result['Items'][0]['AssetGroups']
                    in_asset_group = asoc.isUserInAssetGroup(user,group)
                    if in_asset_group['Items']:
                        asoc.logger(user + " user already a member of Asset Group: " + group)
                    else:
                        # create list of asset group IDs to which User belongs
                        # this will be updated with the ID of the missing Asset Group
                        asoc.logger("Adding user " + user + " to Asset Group " + group)
                        asset_group_ids = []
                        for asset_group in user_asset_groups:
                            asset_group_ids.append(asset_group['Id'])
                        new_asset_group = asoc.getAssetGroupByName(group)['Items'][0]['Id']
                        asset_group_ids.append(new_asset_group)
                        asoc.updateUserAssetGroups(uid,asset_group_ids)

                else:
                    asoc.logger(user+" user does NOT exist in ASoC.  Sending invite.")
                    asset_group_ids = []
                    new_asset_group = asoc.getAssetGroupByName(group)['Items'][0]['Id']
                    asset_group_ids.append(new_asset_group)
                    asoc.inviteUsers(user,asset_group_ids,role_uid)
                    
asoc.logger("---Ending script execution---")                
