#!/usr/bin/env python3

from ldap3 import Server, Connection, NTLM, SUBTREE
import csv


# ==========================
# LDAP Configuration
# ==========================

LDAP_SERVER = ""
LDAP_USER = "domain\\user"
LDAP_PASSWORD = ""

BASE_DN = ""


# ==========================
# Connect LDAP
# ==========================

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


# ==========================
# Find DAA Groups
# ==========================

def get_daa_groups(conn):

    search_filter = (
        "(&(objectClass=group)(cn=DAA_*))"
    )

    conn.search(
        BASE_DN,
        search_filter,
        search_scope=SUBTREE,
        attributes=[
            "cn",
            "distinguishedName",
            "member"
        ]
    )

    return conn.entries



# ==========================
# Get Group Members
# ==========================

def get_group_members(conn, group_dn):

    members=[]

    conn.search(
        BASE_DN,
        f"(&(objectClass=user)(memberOf={group_dn}))",
        attributes=[
            "sAMAccountName",
            "mail"
        ],
        search_scope=SUBTREE
    )


    for user in conn.entries:

        email = user.mail.value

        if email:
            members.append(email.lower())

    return members



# ==========================
# Export CSV
# ==========================

def export_csv(groups):

    with open(
        "daa_groups_export.csv",
        "w",
        newline=""
    ) as file:

        writer = csv.writer(file)

        writer.writerow(
            [
                "AD_Group",
                "ASoC_Asset_Group",
                "Member"
            ]
        )


        for group in groups:

            ad_group = group.cn.value

            # Remove DAA_ prefix
            asoc_group = ad_group.replace(
                "DAA_",
                "",
                1
            )


            members = get_group_members(
                conn,
                group.distinguishedName.value
            )


            if members:

                for member in members:

                    writer.writerow(
                        [
                            ad_group,
                            asoc_group,
                            member
                        ]
                    )

            else:

                writer.writerow(
                    [
                        ad_group,
                        asoc_group,
                        ""
                    ]
                )


# ==========================
# Main
# ==========================


conn = connect_ldap()

groups = get_daa_groups(conn)


print(
    f"Found {len(groups)} DAA groups"
)


export_csv(groups)


print(
    "CSV export complete"
)
