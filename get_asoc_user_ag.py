#!/usr/bin/env python3

import csv
import requests

# ======================================================
# Configuration
# ======================================================

API_BASE = "https://cloud.appscan.com/api/v4"

KEY_ID = ""
KEY_SECRET = ""

OUTPUT_FILE = "asoc_asset_groups.csv"

# ======================================================
# Authentication
# ======================================================

def get_access_token():

    url = f"{API_BASE}/Account/ApiKeyLogin"

    payload = {
        "KeyId": KEY_ID,
        "KeySecret": KEY_SECRET
    }

    r = requests.post(url, json=payload)
    r.raise_for_status()

    return r.json()["Token"]


# ======================================================
# Get All Asset Groups
# ======================================================

def get_asset_groups(token):

    headers = {
        "Authorization": f"Bearer {token}"
    }

    r = requests.get(
        f"{API_BASE}/AssetGroups",
        headers=headers,
        params={
            "$top": 5000,
            "$select": "Id,Name"
        }
    )

    r.raise_for_status()

    return r.json()["Items"]


# ======================================================
# Get All Users
# ======================================================

def get_users(token):

    headers = {
        "Authorization": f"Bearer {token}"
    }

    r = requests.get(
        f"{API_BASE}/User",
        headers=headers,
        params={
            "$top": 5000,
            "$expand": "AssetGroups"
        }
    )

    r.raise_for_status()

    return r.json()["Items"]


# ======================================================
# Main
# ======================================================

def main():

    print("Authenticating...")
    token = get_access_token()

    print("Authentication successful.\n")

    print("Retrieving Asset Groups...")
    asset_groups = get_asset_groups(token)

    print(f"Found {len(asset_groups)} Asset Groups")

    print("Retrieving Users...")
    users = get_users(token)

    print(f"Found {len(users)} Users\n")

    #
    # Build Asset Group dictionary
    #

    group_members = {}

    for group in asset_groups:

        group_members[group["Id"]] = {
            "Name": group["Name"],
            "Members": []
        }

    #
    # Populate members for each Asset Group
    #

    for user in users:

        username = user["UserName"]

        for group in user.get("AssetGroups", []):

            group_id = group["Id"]

            if group_id in group_members:

                group_members[group_id]["Members"].append(username)

    #
    # Export CSV
    #

    print(f"Writing {OUTPUT_FILE}...")

    with open(OUTPUT_FILE, "w", newline="", encoding="utf-8") as csvfile:

        writer = csv.writer(csvfile)

        writer.writerow([
            "AD Group Name",
            "ASoC Asset Group",
            "User"
        ])

        for group in sorted(
                group_members.values(),
                key=lambda x: x["Name"].lower()):

            ad_group_name = f"DAA_{group['Name']}"

            members = sorted(group["Members"])

            if members:

                for member in members:

                    writer.writerow([
                        ad_group_name,
                        group["Name"],
                        member
                    ])

            else:

                writer.writerow([
                    ad_group_name,
                    group["Name"],
                    ""
                ])

    print(f"\nCSV successfully written to '{OUTPUT_FILE}'.")


if __name__ == "__main__":
    main()
