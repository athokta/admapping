#!interpreter [optional-arg]
# -*- coding: utf-8 -*-

"""
    Migration from AD-mastered to Okta mastered users
    Part 1
    Tested on: Okta Version 2020.12.0
    Okta Inc.
"""

# Built-in/Generic Imports
import requests
import json
import re
import csv
import getpass
import time
from dotenv import load_dotenv
import os
import urllib

# Header data
__author__ = 'Anton Herber'
__copyright__ = 'Copyright 2020, Okta-AD-migration'
__version__ = '1.0.0'
__email__ = 'anton.herber@okta.com'
__status__ = 'Lab-tested'

load_dotenv()
# Store these in a local .env file.
oktadomain = os.getenv('OKTA_ORG_URL') # eg https://XXX.okta.com
username = os.getenv('OKTA_USERNAME')
okta_admin_url = os.getenv('OKTA_ADMIN_URL')
apikey = os.getenv('APIKEY')
addomain = os.getenv('ADDOMAIN')
oktaadid = os.getenv('OKTAADID')
OUgroupPrefix = os.getenv('OUGROUPPREFIX')
DCsuffix = os.getenv('DCSUFFIX')
hookfile = os.getenv('HOOKFILE')
logfile = os.getenv('LOGFILE')

# Users endpoint
usersep = oktadomain + '/api/v1/users/'
# Groups endpoint
groupsep = oktadomain + '/api/v1/groups'
# header with APIKEY authorization
# Apps endpoint
appsep = oktadomain + '/api/v1/apps'
headers = {'Authorization': 'SSWS ' + apikey, 'Accept': 'application/json', 'Content-Type': 'application/json'}

def main():
    # sign in and get admin token
    sign_in()
    user = get_user('me')
    admin_xsrf_token = admin_sign_in()
    # create shadow groups for AD groups and link them
    groupSearch(admin_xsrf_token)
    # create shadow groups for OUs and link them
    ouSearch(admin_xsrf_token)

def ouSearch(admin_xsrf_token):
    # Get all users
    u = requests.get(usersep, headers=headers)
    check_limit(u.headers["X-Rate-Limit-Remaining"])
    users = json.loads(u.text)
    # get unique OU list
    auxiliaryList = getUniqueOUlist(users)

    # write AD managed users to a file to use later for the password hook
    with open(hookfile, 'w') as hookf:
        for user in users:
            adDN = user.get('profile').get('adDN')
            if adDN is not None:
                hookf.write(user.get('id') + '\n')
    exit()

    # Now read users again and list members of those OUs
    # commands to alter users for Hooks to bash script
    print ("2. Creating OU Groups ...\n--------------------------")
    for ouGroup in auxiliaryList:
        memberOfOUDNs = []
        memberOfOUIDs = []
        members = []
        for user in users:
            adDN = user.get('profile').get('adDN')
            firstName = user.get('profile').get('firstName')
            lastName = user.get('profile').get('lastName')
            if adDN is not None:
                # write User commands for Hooks
                #with open(hookfile, 'a') as curlfile:
                #    curlfile.write(composeCURL(user.get('id')) + '\n')
                # remove CN and last part of DN part
                OUstring = ""
                for ous in adDN.split(','):
                    if ("OU=" in ous):
                        OUstring += ous + "-"
                OUstring = OUstring[:-1]
                if (ouGroup == OUstring):
                    memberOfOUDNs.append(adDN.encode("utf-8"))
                    memberOfOUIDs.append(user.get('id').encode("utf-8"))
                    members.append([user.get('id').encode("utf-8"),firstName.encode("utf-8"),lastName.encode("utf-8")])
        removeOUsFromgroup = re.sub("OU=", '', ouGroup)

        # POST to create group
        data = '{\"profile\": {\"name\": \"' + OUgroupPrefix + removeOUsFromgroup + '\",\"description\": \"' + "OU Group for " + ouGroup + '\"}}'
        print ("\tWill create Group: >" + OUgroupPrefix + removeOUsFromgroup + "< to represent OU >" + ouGroup + "<")
        x = requests.post(groupsep, headers=headers, data = data)
        check_limit(x.headers["X-Rate-Limit-Remaining"])
        OUgroups = json.loads(x.text)
        print ("\tGroup with ID:\t" +  OUgroups.get('id') + " created")

        # print output
        print ("\tOU:\t\t" + ouGroup.encode("utf-8"))
        print ("\tNew Okta Group:\t" + OUgroupPrefix + removeOUsFromgroup)
        print ("\twith members");
        i=0
        for member in members:
            print ("\t\t" + members[i][0] + "(" + members[i][1] + " " + members[i][2] + ")")
            i = i+1

        # add members to group
        i=0
        for member in members:
            x = requests.put(groupsep + "/" + OUgroups.get('id') + "/users/" + members[i][0], headers=headers)
            check_limit(x.headers["X-Rate-Limit-Remaining"])
            if (x.status_code == 204):
                print ("\tMember: " + members[i][0] + " added to group")
            else:
                print ("\t\tError adding member: " + members[i][0] + " to group")
            i = i+1

        # map group to OU. Add Suffix and replace the - with the ,
        ouGroup = re.sub(r'-OU', ',OU', ouGroup) + "," + DCsuffix
        print ("\tGroup: " + OUgroups.get('id') + " will be mapped to " + ouGroup.lower() + "\n")
        mapGroupToOU(OUgroups.get('id'), ouGroup.lower(), OUgroups.get('profile').get('name'), admin_xsrf_token)
        #pressed = raw_input("E: Next OU ...")

    print ("\n\tFinished mapping Groups to OUs.\n\nPerform all the necessary steps before you run >alterUsers.py< with: >" + hookfile + "<")


def writeLog(entry):
    with open(logfile, 'a') as LOG:
        LOG.write(entry + '\n')

# unique OU DNs
def getUniqueOUlist(users):
    dnList = []
    auxiliaryList = []
    # get ID and DN of users
    # use the DN, extract the part between CN and DC
    # put them into an array, make them unique and sort it
    # Output: List of OUs the users are in
    OUstring = ""
    for user in users:
        adDN = user.get('profile').get('adDN')
        if adDN is not None:
            # remove CN and DC parts
            for ous in adDN.split(','):
                if ("OU=" in ous):
                    OUstring += ous + "-"
            OUstring = OUstring[:-1]
            dnList.append(OUstring)
            OUstring = ""

    # get only unique List of DNs
    for dn in dnList:
        if dn not in auxiliaryList:
            auxiliaryList.append(dn)
    # sort DNs
    auxiliaryList.sort()
    return auxiliaryList

# Search for Okta group
def searchForGroup(groupname):
    groupsepsearch = groupsep + '?search=type eq "OKTA_GROUP"  and profile.name sw "' + groupname + '"'
    # get all groups
    g = requests.get(groupsepsearch, headers=headers)
    check_limit(g.headers["X-Rate-Limit-Remaining"])
    groups = json.loads(g.text)

    id = "empty"
    for group in groups:
        id = group.get('id')

    if "empty" in id:
        return "false"
    else:
        return "true"

# create shadow group for AD groups
def groupSearch(xsrftoken):
    # grouplist
    groupList = []

    print ("1. Creating shadow groups for AD groups...\n-----------------------------------------")
    groupsepsearch = groupsep + '?search=type eq "APP_GROUP" and profile.windowsDomainQualifiedName sw "' + addomain + '"'
    # get all groups
    g = requests.get(groupsepsearch, headers=headers)
    check_limit(g.headers["X-Rate-Limit-Remaining"])
    groups = json.loads(g.text)

    # get AD Groups and their members
    for group in groups:
        memberList = []
        OUstringForGroup = ""
        id = group.get('id')
        groupDN = group.get('profile').get('dn')
        FullgroupDN = groupDN

        # search for Okta group, if available, skip
        # and write logfile
        if "true" in searchForGroup(group.get('profile').get('name')):
            print ("WARNING: Group >" + group.get('profile').get('name') + "< already in Okta, won't create. Please verify manually!")
            writeLog("Group >" + group.get('profile').get('name') + "/" + group.get('profile').get('windowsDomainQualifiedName') + "< already in Okta, won't create. Please verify manually!")
            continue

        # create shadow group (must be named like the one in the AD, or no match is possible)
        if groupDN is not None:
            # remove CN and DC parts
            GroupOUFullDN = ""
            for ous in groupDN.split(','):
                if ("OU=" in ous):
                    GroupOUFullDN += ous + ","
            GroupOUFullDN = GroupOUFullDN[:-1]
            groupDN = re.sub('CN=', '', groupDN)
            groupName = groupDN.split(',')[0]
            print ("New Group: " + groupName + " for " + FullgroupDN)
        # get members
        m = requests.get(groupsep +'/' + id + '/users', headers=headers)
        check_limit(m.headers["X-Rate-Limit-Remaining"])
        members = json.loads(m.text)
        for member in members:
            memberList.append([member.get('id').encode("utf-8"), member.get('profile').get('firstName').encode("utf-8"), member.get('profile').get('lastName').encode("utf-8")])

        if groupDN is not None:
            groupList.append(groupDN)

        # print members of group
        print ("\tAD Group: " + groupName + " has the following members: ")
        if memberList:
            i=0
            for member in memberList:
                print ("\t\t" + memberList[i][0] + "(" + memberList[i][1] + " " + memberList[i][2] + ")")
                i = i+1
        else:
            print ("\t\tNo members")

        #pressed = raw_input("E: Will now create shadow groups, add users and map group to AD ...")
        # Create shadow Group for every group now
        # POST to create group
        data = '{\"profile\": {\"name\": \"' + groupName + '\",\"description\": \"' + "Shadow Group for " + FullgroupDN + '\"}}'
        print ("\tWill create Group: >" + groupName + "< to represent AD group >" + FullgroupDN + "<")
        x = requests.post(groupsep, headers=headers, data=data)
        check_limit(x.headers["X-Rate-Limit-Remaining"])
        ADgroup = json.loads(x.text)
        print ("\tGroup with ID:\t" +  ADgroup.get('id') + " created")
        # add members to new group
        i=0
        for member in memberList:
            x = requests.put(groupsep + "/" + ADgroup.get('id') + "/users/" + memberList[i][0], headers=headers)
            check_limit(x.headers["X-Rate-Limit-Remaining"])
            if (x.status_code == 204):
                print ("\tMember: " + memberList[i][0] + " added to group")
            else:
                print ("\t\tError adding member: " + memberList[i][0] + " to group")
            i = i+1

        # if AD group has application assignments, mapping is not possible
        # New group has to be assigned to the app first. Otherwise the users will be lost during the mapping process
        # AD group must be removed afterwards from the app, otherwise mapping is not possible
        # then
        add_group_to_apps(id, ADgroup.get('id'))

        # map group to OU
        status = mapGroupToAD(ADgroup.get('id'), ADgroup.get('profile').get('name'), GroupOUFullDN + "," + DCsuffix, oktaadid, xsrftoken)
        if "true" in status:
            print ("\tSUCCESS: Group mapped to AD")
        else:
            print ("\tWARNING: Could not push and map group to AD Group, please check manually.")
            writeLog("Group >" + groupName + "< could not be mapped to: >" + GroupOUFullDN + "," + DCsuffix + "<")
        pressed = raw_input("E: ENTER for Next Group ...")

# read apps assigned to the group and assign the new group to the apps too
# then remove the membership
def add_group_to_apps(adgroupid, oktagroupid):
    result = requests.get(groupsep + "/" + adgroupid + "/apps", headers=headers)
    check_limit(result.headers["X-Rate-Limit-Remaining"])
    groupapps = json.loads(result.text)

    addedStatus = "true"
    for app in groupapps:
        print ("\tGroup: " + adgroupid + " is assigned to APP: " + app.get("id") + "(" + app.get("label") + ")")
        print ("\tAssigning new Group: " + oktagroupid + " to APP: " + app.get("id") + "(" + app.get("label") + ")")
        addgroup = requests.put(appsep + "/" + app.get("id") + "/groups/" + oktagroupid, headers=headers)
        check_limit(addgroup.headers["X-Rate-Limit-Remaining"])
        added = json.loads(addgroup.text)
        if oktagroupid in added.get("id"):
            print ("\tSUCCESS: Group assigned to application")
            delgroupfromapp = requests.delete(appsep + "/" + app.get("id") + "/groups/" + adgroupid, headers=headers)
            check_limit(result.headers["X-Rate-Limit-Remaining"])
            if delgroupfromapp.status_code == 204:
                print ("\tSUCCESS: AD group removed from APP")
            else:
                print ("\tWARNING: AD group could not be removed from APP")
        else:
            print ("\tWARNING: Group: " + adgroupid + " could not be assigned to: " + app.get("id") + " (" + app.get("label") + ")")
            writeLog("\tWARNING: Group: " + adgroupid + " could not be assigned to: " + app.get("id") + " (" + app.get("label") + ")")
            addedStatus = "false"

    if "false" in addedStatus:
        print ("\tThe Okta group could not be assigned to at least to one app. Won't remove the membership. Conflict has to be resolved manually.")

session = requests.Session()

# check rate limit and wait if needed
def check_limit(current_limit):
    print("\tRate limit remaining: " + current_limit)
    if current_limit < 20:
        print("\tWill sleep for 5 seconds...")
        time.sleep(5)

# normal sign in
def sign_in():
    print('URL:', oktadomain)
    print('Username:', username)
    password = getpass.getpass()
    #password = "<automaticifneeded>"

    print('Signing in...')
    response = session.post(oktadomain + '/api/v1/authn', json={'username': username, 'password': password})
    authn = response.json()
    if not response.ok:
        print(authn['errorSummary'])
        exit()

    if authn['status'] == 'MFA_REQUIRED':
        token = send_push(authn['_embedded']['factors'], authn['stateToken'])
    else:
        token = authn['sessionToken']

    session.get(oktadomain + '/login/sessionCookieRedirect?redirectUrl=/&token=' + token )

# get Working Set
def getADGroupMatch(oktaadid, selectedou, groupname, xsrftoken):
    headers = {'Accept': 'application/json', 'Content-Type': 'application/json', 'x-okta-xsrftoken': xsrftoken}
    response = session.get(okta_admin_url + '/api/internal/instance/' + oktaadid + '/grouppush/autocompleteADAppGroups?selectedOU=' + selectedou.lower() + '&q=' + groupname, headers=headers)
    match = re.search(r'"appGroupId":"(.+)\"}', response.text)
    check_limit(response.headers["X-Rate-Limit-Remaining"])
    if not match:
        print('Group Match not found')
        return "false"
    else:
        appgroupid = match.group(1)
        return appgroupid

# admin sign in
def admin_sign_in():
    response = session.get(oktadomain + '/home/admin-entry')
    match = re.search(r'<span.* id="_xsrfToken">(.*)</span>', response.text)
    if not match:
        print('admin_sign_in: token not found. Go to Security > General and disable Multifactor for Administrators.')
        exit()
    admin_xsrf_token = match.group(1)
    return admin_xsrf_token

# get user
def get_user(userid):
    user = session.get(oktadomain + '/api/v1/users/' + userid).json()
    #print('\nUser:')
    #print(user)
    return user

# Map group to AD group
def mapGroupToAD(groupid, groupname, adgroupou, adinstance, xsrftoken):
    appgroupid = getADGroupMatch(oktaadid, adgroupou, groupname, xsrftoken)
    headers = {'Accept': 'application/json', 'Content-Type': 'application/json', 'x-okta-xsrftoken': xsrftoken}
    data = '{\"status\":\"ACTIVE\",\"userGroupId\":\"' + groupid + '\",\"existingAppGroupId\":\"' + appgroupid + '\",\"groupPushAttributes\":{\
        \"groupScope\":\"GLOBAL\",\"groupType\":\"SECURITY\",\"distinguishedName\":\
        \"' + adgroupou.lower() + '\",\"samAccountName\":\"' + groupname + '\"}}'
    response = session.post(okta_admin_url + '/api/internal/instance/' + adinstance + '/grouppush', headers=headers, data=data)
    if response.status_code == 200:
        return "true"
    else:
        return "false"

# Map group to OU
def mapGroupToOU(groupid, ou, groupname, xsrftoken):
    wsid = getWorkingSet(groupid, xsrftoken)
    headers = {'Accept': 'application/json', 'Content-Type': 'application/json', 'x-okta-xsrftoken': xsrftoken}
    data = '{\"assignments\": {\"' + oktaadid + '\": {\"extensibleProfile[adCountryCode]\": \"\",\
        \"extensibleProfile[co]\": \"\", \"extensibleProfile[description]\": \"\",\
        \"extensibleProfile[division]\": \"\", \"extensibleProfile[facsimileTelephoneNumber]\": \"\",\
        \"extensibleProfile[preferredLanguage]\": \"\", \"organizationalUnit\": \"' + ou +'\"}},\
        \"workingSetId\":{\"' + wsid + '\":null},\"appInstanceIdsToRemove\":{}}'
    response = session.post(okta_admin_url + '/admin/group/' + groupid + '/submitApps', headers=headers, data = data)

# get Working Set
def getWorkingSet(groupid, xsrftoken):
    data = ''
    headers = {'Accept': 'application/json', 'Content-Type': 'application/json', 'x-okta-xsrftoken': xsrftoken}
    response = session.post(okta_admin_url + '/admin/group/' + groupid + '/workingSetApps', headers=headers, data = data)
    match = re.search(r'"workingSetId":"(.+)\","pendo"', response.text)
    if not match:
        print('Working Set ID not found, cannot map group. Won\'t continue. Fix this first.')
        exit()
    workingsetid = match.group(1)
    return workingsetid

main()
