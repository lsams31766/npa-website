#!/usr/bin/python3
from ldap3 import ALL_ATTRIBUTES, LEVEL, MODIFY_ADD, MODIFY_DELETE, MODIFY_REPLACE, BASE, NTLM, SUBTREE, ASYNC, ALL, Server, Connection, AUTO_BIND_TLS_BEFORE_BIND
import ldap3
from contextlib import contextmanager
import sys
sys.path.append('/idm/ldap/scripts/common')
import databaseUtil as db
# from cachetools.keys import hashkeypi
import functools
from app import appLog, BASE_DIR
import re
import os
import json
from queries import *
     

ENV = 'prod'

def search(con, search_base, search_filter, search_scope=SUBTREE, attributes=None, paged_size=500):
    return con.extend.standard.paged_search(search_base = search_base, search_filter=search_filter, search_scope=search_scope, attributes=attributes, paged_size=paged_size, generator=False)

def getv(entry, attr):
    if attr in entry and entry[attr].values:
        return entry[attr].values
    return []

def listify(variable):
    if isinstance(variable, list):
        return variable
    elif variable is None:
        return []
    else:
        return [variable]
    
def flattenList(data):
    if not data:
        return None
    if isinstance(data, list):
        return ', '.join(data) 
    return data

def truncList(data):
    if not data:
        return None
    if isinstance(data, list):
        return data[0]
    return data

def getED():
    if ENV == 'prod':
        return db.getConnection('enterpriseDirectory') 
    return None

def getFR():
    if ENV == 'prod':
        server = Server('ldapsec.aws.bms.com', port=636, use_ssl=True)
        return Connection(server, auto_bind=True, check_names=True, read_only=True, raise_exceptions=False)
    return None

def getAM():
    if ENV == 'prod':
        server = Server('smusdir.bms.com')
        return Connection(server, auto_bind=True, check_names=True, read_only=True, raise_exceptions=False)
    return None

def getAD():
    if ENV == 'prod':
        server = Server('adjoin-na.one.ads.bms.com:636', use_ssl=True)
        #return Connection(server, 'CN=NPALOOKUP,OU=Service Accounts,OU=IMSS,DC=one,DC=ads,DC=bms,DC=com', "!OqMy2MOya!rm$U", auto_bind=True)
        return Connection(server, 'CN=APP_NPADMIN,OU=Service Accounts,OU=IMSS,DC=one,DC=ads,DC=bms,DC=com', "P4oCL2efISwlWr1", auto_bind=True)
        # P4oCL2efISwlWr1
    return None

def getCA():
    if ENV == 'prod':
        return db.getConnection('cyberark')
    return None

def getPeopleCon():
    type ="mysql"
    server = "accengdbprod.c9pxjgrv7vhh.us-east-1.rds.amazonaws.com"
    username = "zbtools"
    passwordEncoded = "RDBicjAhNzRwQG55"
    password = db.decode(passwordEncoded)
    port = 3306
    database = "ldap_db"
    return db.mysql.connector.connect(host=server, user=username, password=password, database=database, port=port, ssl_disabled=True)

def getNPADatabase():
    if ENV == 'prod':
        return db.getConnection('zbt') 
    return None

def getFR_NPA():
    con = db.getConnectionFR_SSL('fr-npa')
    return con

def getAM_NPA():
    con = db.getConnection('am-npa')
    return con

def getEDNonpeople():
    print('GetEDNonpeople')
    with getED() as con:
        search(con, search_base='ou=nonpeople,o=bms.com', search_filter='(objectclass=*)', search_scope=LEVEL, attributes=["cn", "uid", "manager", "secretary", "description"])
        results = []
        for entry in con.entries:
            data = {
                'in_ed': True,
                'source': 'ED',
                'dn': entry.entry_dn,
                'uid': getv(entry, 'uid'),
                'cn': getv(entry, 'cn'),
                'manager': getv(entry, 'manager'),
                'secretary': getv(entry, 'secretary'),
                'description': getv(entry, 'description'),
                'last_source': 'ED'
            }
            results.append(data)
        return results

def getAMNonpeople(env='prod'):
    print('getAMNonPeople')
    with getAM() as con:
        search(con, search_base='ou=nonpeople,o=bms.com', search_filter='(objectclass=*)', search_scope=LEVEL, attributes=["cn", "uid", "manager", "secretary", "description"])
        results = []
        for entry in con.entries:
            data = {
                'in_am': True,
                'source': 'am',
                'dn': entry.entry_dn,
                'uid': getv(entry, 'uid'),
                'cn': getv(entry, 'cn'),
                'manager': getv(entry, 'manager'),
                'secretary': getv(entry, 'secretary'),
                'description': getv(entry, 'description'),
                'last_source': 'am'
            }
            results.append(data)
        return results
    
def getFRNonpeople(env='prod'):
    # Important! 8/6/2024 
    # Ad per management decision: 
    #   we will not read from ED
    #   ALSO: when reading FR, name it ED in the SQL database
    print('getFRNonPeople')
    with getFR() as con:
        search(con, search_base='ou=nonpeople,o=bms.com', search_filter='(objectclass=*)', search_scope=LEVEL, attributes=["cn", "uid", "manager", "secretary", "description","bmsprivtier"])
        results = []
        for entry in con.entries:
            data = {
                'in_fr': True,
                'source': 'ED',
                'dn': entry.entry_dn,
                'uid': getv(entry, 'uid'),
                'cn': getv(entry, 'cn'),
                'tier':getv(entry, 'bmsprivtier'),
                'manager': getv(entry, 'manager'),
                'secretary': getv(entry, 'secretary'),
                'description': fix_chars_in_list(getv(entry, 'description')),
                'last_source': 'FR'
            }
            results.append(data)
        return results

def fix_chars_in_list(l):
    out_list = []
    for item in l:
        # if 'Used to limit a' in item:
        #     print('before',item)
        #     item = item.replace("'","")
        #     item = item.replace('"','')
        #     print('after',item)
        #     exit(0)
        item = item.replace("'","")
        item = item.replace('"','')
        out_list.append(item)
    return out_list
    
def getADNonpeople(env='prod',search_dn=None):
    print('getADNonpeople')
    if search_dn != None:
        comma_pos = search_dn.find(',')
        search_filter = '(' + search_dn[:comma_pos] + ')'
    else:
        search_filter = '(objectclass=*)'
    with getAD() as con:
        search(con, search_base='OU=Service Accounts,OU=IMSS,DC=one,DC=ads,DC=bms,DC=com', search_filter=search_filter, search_scope=LEVEL, attributes=["cn", "uid", "manager", "secretary", "description", "samaccountname","bmsprivtier"])
        results = []
        for entry in con.entries:
            data = {
                'in_ad': True,
                'source': 'AD',
                'dn': entry.entry_dn,
                'uid': getv(entry, 'samaccountname'),
                'cn': getv(entry, 'cn'),
                'manager': getv(entry, 'manager'),
                'secretary': getv(entry, 'secretary'),
                'description': fix_chars_in_list(getv(entry, 'description')),
                'tier': getv(entry, 'bmsprivtier'),
                # 'bmsadapprover': getv(entry, 'bmsadapprover'), # get owners from description
                'last_source': 'AD'
            }
            # note owners may appear in description as:
            # (Owners: polyanss & orcutte)
            try:
                if data['description'] and 'Owners' in data['description'][0]:
                    desc = data['description'][0]
                    owners_pos = desc.find('Owners:') 
                    s_owners = desc[owners_pos+8:]
                    if '&' in s_owners:
                        owners_split = s_owners.split('&')
                    elif ',' in s_owners:
                        owners_split = s_owners.split(',') 
                    else:
                        owners_split = s_owners.split(' ')
                    if owners_split[0]:
                        data['manager'] = [owners_split[0].replace(' ','')]
                    if owners_split[1]:
                        sec = owners_split[1].replace(' ','')
                        data['secretary'] = [sec.replace(')','')]
            except:
                print('COULD not get AD npa for ', data['dn'])
            results.append(data)
        return results
    
def getCANonpeople(env='prod'):
    print('getCANonpeople')
    con = getCA()
    cur = con.cursor()
    query = '''SELECT CAOPObjectPropertyId as pid,
    MAX(CAOPObjectPropertyName) AS name,
    MAX(CAOPSafeId) AS safe,
    MAX(CAOPFileId) AS f,
    MAX(CAOPObjectPropertyValue) as pv,
    MAX(CAOPOptions) as options
    FROM CAObjectProperties
    GROUP BY CAOPObjectPropertyId;'''
    
    cur.execute(query)
    results = cur.fetchall()
    cur.close()
    con.close()
    table = []
    for pid, name, safe, f, value, options in results:
#    for pid, name in results:
        data = {
            'in_ca': True,
            'source': 'ca',
            'dn': pid,
            'uid': name,
#            'cn': '',
            'cn': value,
            'manager': [],
            'secretary': [],
            'description': [
                f"CAOPFileId: {f}, CAOPSafeId: {safe}, CAOPOptions: # {options}"
            ]
#            'description':''
        }
        table.append(data)

    return table

def getAllNonpeople():
    # sources = [getAMNonpeople, getEDNonpeople, getADNonpeople, getFRNonpeople]
    # sources = [getEDNonpeople, getADNonpeople, getFRNonpeople] # OLD CODE
    
    # Important! 8/6/2024 
    # A2 per management decision: 
    #   we will not read from ED
    #   ALSO: when reading FR, name it ED in the SQL database
    sources = [getADNonpeople, getFRNonpeople] # OLD CODE
    allData = []
    for sourceFunction in sources:
        try:
            sourceData = sourceFunction()
            allData.extend(sourceData)
        except Exception as e:
            print(f"Error fetching data from {sourceFunction.__name__}: {e}")
    return allData


def executeQuery(query, params):
    try:
        with getNPADatabase() as con:
            cur = con.cursor(dictionary=True)
            cur.execute(query, params)
            result = cur.fetchall()
            cur.close()
        return result
    except Exception as e:
           appLog.error(f"executeQuery ERROR: {str(e)}")
           return False

def getUserIdentifiers(uid):
    with getED() as ed, getAD() as ad:
        search(ed, search_base='ou=people,o=bms.com', search_filter=f'(uid={uid})', search_scope=LEVEL, attributes=["bmsid", "uid"])
        if ed.entries:
            dn = ed.entries[0].entry_dn
            bmsid = ed.entries[0]['bmsid']
            search(ad, search_base='OU=BMS Users,DC=one,DC=ads,DC=bms,DC=com', search_filter=f'(bmsid={bmsid})', search_scope=LEVEL, attributes=["bmsid", "uid"])
            if ad.entries:
                adn = ad.entries[0].entry_dn
                return uid, dn, adn
    return uid, uid, uid

def searchAllMy(fields, user, query, start=0, length=10, sort_column=0, sort_direction='asc', sources=None):
    # user = 'polyanss'
    # print("**** searchAllMy **** user",user)
    query_lower = f"%{query.lower()}%"
    uid, dn, adn = getUserIdentifiers(user)

    # print("**** searchAllMy 2 ****")
    sql = f"SELECT *, (SELECT COUNT(*) FROM nonpeople_entries WHERE manager IN (%s, %s, %s) OR secretary IN (%s, %s, %s)) as total_records, " \
          f"(SELECT COUNT(*) FROM nonpeople_entries WHERE (manager IN (%s, %s, %s) OR secretary IN (%s, %s, %s)) AND (" + \
          " OR ".join([f"{field} LIKE %s" for field in fields]) + ")) as filtered_records " \
          f"FROM nonpeople_entries WHERE (manager IN (%s, %s, %s) OR secretary IN (%s, %s, %s)) AND (" + \
          " OR ".join([f"{field} LIKE %s" for field in fields]) + ")" + \
          f" ORDER BY " + fields[sort_column + 1] + " " + sort_direction + \
          " LIMIT %s OFFSET %s"

    like_params = [query_lower for _ in fields]
    params = [uid, dn, adn] * 4 + like_params + [uid, dn, adn] * 2 + like_params + [length, start]

    result = executeQuery(sql, params)
    #print("*** result ***")
    #for r in result:
    #    print(r)
    #print("**************")

    if result:
        total_records = result[0]['total_records']
        total_filtered_records = result[0]['filtered_records']
    else:
        total_records = 0
        total_filtered_records = 0

    return {
        'results': result,
        'totalRecords': total_records,
        'totalFilteredRecords': total_filtered_records,
        'headers': fields
    }

def searchColFilter(query='', col_filter={}, start=0, length=100, sort_column=0, sort_direction='asc', sources=None, fields=None, user=None):
    # query is a general search in all fields
    # col_filter is a dictionary of field number to text to search for
    # if query is not none, use that, otherwise use the col_filter
    if user != None:
         uid, dn, adn = getUserIdentifiers(user)
    print(f'### seaarchColFilter, {query}, {col_filter}, {start}, {length}, {sort_column},{sort_direction},{sources},{fields},{user}')
    query_lower = f"%{query.lower()}%"
    # print(f"*** searchColFilter start {start} length {length} ***")
    fields = ['dn', 'uid', 'cn', 'source', 'tier', 'manager', 'secretary', 'description']
    # print("*** searchColFilter process column filter ***")
    fields.pop(0) # not a searchable field
    if user != None:
        all_records_sql, filtered_records_sql, records_sql = get_col_filter_query(fields, col_filter, sort_column, sort_direction, user, uid=uid, dn=dn, adn=adn)
    else:
        all_records_sql, filtered_records_sql, records_sql = get_col_filter_query(fields, col_filter, sort_column, sort_direction)
    records_count = executeQuery(all_records_sql, [])

    filtered_records_count = executeQuery(filtered_records_sql, [])

    params = [length, start]
    try:
        records = executeQuery(records_sql, params)
    except:
        'DID NOT GET RECORDS'
        return {
            'results': {},
            'totalRecords': 0,
            'totalFilteredRecords': 0,
            'headers': fields
        }
    #print("**** result3 ",result3)
  
    #print('total_records', total_records, 'length records', len(records))
    if records_count and filtered_records_count:
        total_records = records_count[0]['total_records']
        total_filtered_records = filtered_records_count[0]['filtered_records']
    else:
        total_records = 0
        total_filtered_records = 0
    #print(f"total {records_count} filtered {filtered_records_count}")
    #print(records)
    #print(fields)
    return {
            'results': records,
            'totalRecords': total_records,
            'totalFilteredRecords': total_filtered_records,
            'headers': fields
        }

def searchCyberark(fields, query, col_filter, start=0, length=100, sort_column=0, sort_direction='asc', sources=None):
    all_records_sql, filtered_records_sql, records_sql = get_ca_search_query(fields, col_filter, sort_column, sort_direction)
    #Count all records, all filtered records, takes too long!
    #filtered_records_count = executeQuery(filtered_records_sql, [])
    ret = executeQuery(all_records_sql, [])
    records_count = ret[0]['count']
    ret = executeQuery(filtered_records_sql, [])
    filtered_records_count = ret[0]['count']
    #print(f"**** records_count {records_count}")
    #print('length,start',length,start)
    records = executeQuery(records_sql, [length,start])
    #filtered_records_count = calculate_nbr_filtered_records(col_filter, fields, records_count)
    print(f"total {records_count} filtered {filtered_records_count}")
    if records_count and filtered_records_count:
        total_records = records_count
        total_filtered_records = filtered_records_count
    else:
        total_records = 0
        total_filtered_records = 0

    return {
            'results': records,
            'totalRecords': total_records,
            'totalFilteredRecords': total_filtered_records,
            'headers': fields
        }

def get_change_log(query, start=0, length=100, sort_column=0, sort_direction='asc'):
    fields = ['date','editor_uid','npa_uid','destination','field_changed','value_changed']
    all_records_sql, filtered_records_sql, records_sql = change_log_query(fields, query, sort_column, sort_direction,length,start)
    records_count = executeQuery(all_records_sql, [])
    query_lower = f"%{query.lower()}%"
    params_filtered = [query_lower] * len(fields)
    #print(f"params_filtered {params_filtered}")
    filtered_records_count = executeQuery(filtered_records_sql, [])
    records = executeQuery(records_sql, [])
    # fix the adate format
    for r in records:
        if r['date']:
            s = r['date'].strftime("%Y-%m-%d %H:%M:%S")
            r['date'] = s
    # print all records
    print('current dates')
    for r in records:
        if r['date']:
            print(r['date'])
    #print(f'get_change_log nbr records {len(records)}')

    if records_count and filtered_records_count:
        total_records = records_count[0]['total_records']
        total_filtered_records = filtered_records_count[0]['filtered_records']
    else:
        total_records = 0
        total_filtered_records = 0

    return {
            'results': records,
            'totalRecords': total_records,
            'totalFilteredRecords': total_filtered_records,
            'headers': fields
        }
 
def make_groups_anchor(group_name):
   # open new tab for this
   # format: '<a  href="{href}">' + group_name + '</a>'
   # and site is https://groups.bms.com/groups/GG_IMSS_PAM_SN_DISC_OWNER
   href = 'https://groups.bms.com/groups/' + group_name
   anchor = '<a  target="_blank" href="'
   anchor += href
   anchor += '">' + group_name + '</a>'
   return anchor


def get_ca_details(safe_id):
    policy_sql = get_ca_policy_ids(safe_id)
    con = getCA()
    cur = con.cursor()    
    cur.execute(policy_sql)
    policy_records = cur.fetchall()
    # print(f'policies for {safe_id} count: {len(policy_records)}')

    owners_sql = get_ca_owners(safe_id)
    cur.execute(owners_sql)
    owners_records = cur.fetchall()
    cur.close()
    con.close()
    # print(f'owners for {safe_id} count: {len(owners_records)}')
    # if more than 5 policies, 5 owners, just return up to 5
    policy_records = [item[0] for item in policy_records]
    fixed_policies = list(set(policy_records))
    s_policies = ', '.join(fixed_policies)
    owners_records = [item[0] for item in owners_records]
    fixed_owners = list(set(owners_records))
    print('before',fixed_owners)
    owner_group = []
    user_group = []
    # only want owners ending in EUSER or OWNER
    for f in fixed_owners:
        if f.upper().endswith('OWNER'):
            owner_group.append(make_groups_anchor(f))
        if f.upper().endswith('EUSER'):
            user_group.append(make_groups_anchor(f))
    print(f'owner_group {owner_group}')
    print(f'user_group {user_group}')
    # requested format
    # Owner Group: : GG_IMSS_PAM_PROD_ITOps_MyoKardia_OWNER
    # User Group: GG_IMSS_PAM_PROD_ITOps_MyoKardia_EUSER
    # we want anchors, and link to: https://groups.bms.com/groups/GG_IMSS_PAM_SN_DISC_OWNER
    prefix = ''
    # var a = '<a onclick="getDetails' + params +   '" href="javascript:void(0)">' + row.safe_name + '</a>'

    if owner_group:
        line1 = 'Owner Group: ' + ','.join(owner_group)
    else:
        line1 = 'Owner Group:'
    if user_group:
        line2 = 'User Group: ' + ','.join(user_group)
    else:
        line2 = 'User Group:'
    s_owners = '</br>'.join([line1,line2])

    return s_policies, s_owners

def lookup_people(entered_name):
    # get up to 10 names close to entered name from people table of ldap_db database
    con = getPeopleCon()
    cur = con.cursor()
    # may need 2 lookups if space in name
    if ' ' in entered_name:
        sql = get_person_lookup_query_with_space(entered_name)
        cur.execute(sql)
        ret = cur.fetchall()
    else:
        sql = get_person_lookup_query(entered_name)
        cur.execute(sql)
        ret = cur.fetchall()
    cur.close()
    con.close()
    # we need format: [{"id": 1, "cn": "Jane"}...]
    # we want these fields:
    fields = ['sn', 'cn', 'givenname', 'bmssite', 'bmssitecode', 'bmspersonassociation','bmsuid'] 
    found_names = []
    for item in ret:
        d = {}
        for n, f in enumerate(item):
            d[fields[n]] = f
        found_names.append(d)
    return found_names

def backup_cyberark():
    print("backup_cyberark")
    sql_cmds = [ 
      "TRUNCATE TABLE ca_name_backup",
      "INSERT INTO ca_name_backup SELECT * FROM ca_name",
      "TRUNCATE TABLE ca_name",
    ]
    con = getNPADatabase()  
    cur = con.cursor()
    for sql in sql_cmds:
        try:
            cur.execute(sql, [])
            con.commit()
        except Exception as e:
            print("backup_cyberark error", str(e))
            print("sql:",sql)
    con.close()
    cur.close()

def get_cyberark_field(d, field_name):
   # d is d_names dict, read from cyberark sql server rows
   # field_name is field, to extract value from, or return empty string if not found 
   if field_name in d:
      return d[field_name]
   return '' # not found

def test_cyberark():
    # look for odd starting chars in name field
    # do not include safes for myokardia - these have myokardia in the safe_name
    myokardia_safes = [str(i) for i in [6287, 6319, 6482, 6483, 6484, 6485, 6486, 6487, 6488, 6489, 6490, 6491, 6492, 7125]]
    myokardia_safes_str = '(' + ','.join(myokardia_safes) + ')'

    sql = f'''SELECT CAOPSafeId, CAOPFileId,
    MAX(CASE WHEN CAOPObjectPropertyName = 'UserName' THEN CAOPObjectPropertyValue END) AS UserName,
    MAX(CASE WHEN CAOPObjectPropertyName = 'Address' THEN CAOPObjectPropertyValue END) AS Address,
    MAX(CASE WHEN CAOPOBjectPropertyName = 'Database' THEN CAOPObjectPropertyValue END) AS Dbase,
    MAX(CASE WHEN CAOPOBjectPropertyName = 'TIER' THEN CAOPObjectPropertyValue END) AS Tier,
    MAX(CASE WHEN CAOPOBjectPropertyName = 'CIID' THEN CAOPObjectPropertyValue END) AS CIID
    FROM CyberArk.dbo.CAObjectProperties
    WHERE CAOPSafeId != 47
    AND CAOPSafeId NOT IN {myokardia_safes_str}
    GROUP BY CAOPSafeId, CAOPFileId;
    '''
    print('read db')
    con = getCA()
    cur = con.cursor()    
    cur.execute(sql)
    results = cur.fetchall()
    cur.close()
    con.close()

    names_issues = set()
    for r in results:
        if r[2] and r[2] != '':  # user_name
            if r[2].startswith(' ') or r[2].startswith('_'):
                if r[2] not in names_issues:
                    names_issues.add(r[2])
    print('names_issues',names_issues)

def synch_cyberark():
    # copy the data, clear ca_name and ca_address tables
    appLog.info(f"synch_cyberark")
    backup_cyberark()

    print("load_ca_to_myql get data from sql server")
    con = getNPADatabase()  
    cur = con.cursor()
    cur.execute("TRUNCATE TABLE ca_name", [])
    con.commit()
    cur.close()
    con.close()

    # do not include safes for myokardia - these have myokardia in the safe_name
    myokardia_safes = [str(i) for i in [6287, 6319, 6482, 6483, 6484, 6485, 6486, 6487, 6488, 6489, 6490, 6491, 6492, 7125]]
    myokardia_safes_str = '(' + ','.join(myokardia_safes) + ')'

    sql = f'''SELECT CAOPSafeId, CAOPFileId,
    MAX(CASE WHEN CAOPObjectPropertyName = 'UserName' THEN CAOPObjectPropertyValue END) AS UserName,
    MAX(CASE WHEN CAOPObjectPropertyName = 'Address' THEN CAOPObjectPropertyValue END) AS Address,
    MAX(CASE WHEN CAOPOBjectPropertyName = 'Database' THEN CAOPObjectPropertyValue END) AS Dbase,
    MAX(CASE WHEN CAOPOBjectPropertyName = 'TIER' THEN CAOPObjectPropertyValue END) AS Tier,
    MAX(CASE WHEN CAOPOBjectPropertyName = 'CIID' THEN CAOPObjectPropertyValue END) AS CIID
    FROM CyberArk.dbo.CAObjectProperties
    WHERE CAOPSafeId != 47
    AND CAOPSafeId NOT IN {myokardia_safes_str}
    GROUP BY CAOPSafeId, CAOPFileId;
    '''
    print('read db')
    con = getCA()
    cur = con.cursor()    
    cur.execute(sql)
    results = cur.fetchall()
    cur.close()
    con.close()

    # count fields
    nbr_user = 0
    nbr_addr = 0
    nbr_db = 0
    nbr_tier = 0
    nbr_ci_id = 0
    fixes = 0
    for r in results:
        if r[2] and r[2] != '':
            nbr_user += 1
        if r[3] and r[3] != '':
            nbr_addr += 1
        if r[4] and r[4] != '':
            nbr_db += 1
        if r[5] and r[5] != '':
            nbr_tier += 1
        if r[6] and r[6] != '':
            nbr_ci_id += 1
    print(f"nbr_user {nbr_user} nbr_addr {nbr_addr} nbr_db {nbr_db} nbr_tier {nbr_tier}  nbr_ci_id {nbr_ci_id} fixes{fixes}")

    # put into ca_name_backup
    # order is safe_id, file_id, user_name, (no address), db, tier, ci_id
    print(f'save to ca_name {len(results)} records')
    appLog.info(f"synch_cyberark save to ca_name {len(results)} records")
    con = getNPADatabase()  
    cur = con.cursor()
    count = 0
    fixes = 0
    for item in results:
        # need some cleanup, some names start with spaces - remove leading spaces
        # some start with '_' remove the leading underlines
        count += 1
        if count % 100 == 0:
            print('.',end='',flush=True)
        # fix names starting with ' ' or '_'
        if item[2] and item[2] != '':
            user_name = item[2]
            if user_name.startswith(' ') or user_name.startswith('_'):
                user_name = user_name[1:]
                fixes += 1
        else:
            user_name = None
        sql = f"""INSERT INTO ca_name (safe_id, file_id, user_name, address, db, tier, ci_id) VALUES ('{item[0]}', '{item[1]}', '{user_name}', '{item[3]}', '{item[4]}', '{item[5]}', '{item[6]}')"""
        try:
            cur.execute(sql, [])
            con.commit()
        except:
            print(f'ERROR could not insert with item {item}')
            appLog.info(f"synch_cyberark could not insert with item {item}")
    print(f'done, fixed {fixes} items')

    # load safe names
    print("load_ca_to_myql get safe names")
    sql = '''SELECT CASSafeName, CASSafeID FROM CyberArk.dbo.CASafes'''
    con = getCA()
    cur = con.cursor()    
    cur.execute(sql)
    results = cur.fetchall()
    cur.close()
    con.close()

    # put into ca_name table
    print(f"load_ca_to_myql load safe names, {len(results)} records")
    appLog.info(f"load safe name into ca_name table with {len(results)} records")
    con = getNPADatabase()  
    cur = con.cursor()
    # only save unique
    count = 0
    for item in set(results):
        # item in form (safe_id,'UserName',value)
        count += 1
        if count % 100 == 0:
            print('.', end='', flush=True)
        sql = f"UPDATE ca_name SET safe_name = '{item[0]}'"
        sql += f' WHERE safe_id = {item[1]}'
        try: 
            cur.execute(sql, [])
            con.commit()
        except:
            print(f'ERROR could not insert safe name with item {item}')
    print('done')

def clean_ca_entries():
    # in mysql db, names may start with space, remove these spaces
    sql = 'SELECT user_name from ca_name'
    records = executeQuery(sql, [])
    print(f'found {len(records)} records')
    valid_start = 'abcdefghijklmnopqrstuvwxyz0123456789'
    # find records starting with space
    bad_names = []
    for r in records:
        name = r['user_name']
        if name[0].lower() not in valid_start:
            bad_names.append(name)
    print(f'need to fix {len(bad_names)} records')
    # can we replace the bad names - try the first
    con = getNPADatabase()  
    cur = con.cursor()
    for bn in bad_names:
        old_name = bn
        new_name = bn[1:]
        sql = 'UPDATE ca_name SET user_name = '
        sql += f"'{new_name}'"
        sql += f" WHERE user_name = '{old_name}'"
        cur.execute(sql, [])
        con.commit()

def get_user_dn(uid):
    # the the dn for this user 
    with getED() as con:
        search_filter = f'(uid={uid})'
        search(con, search_base='ou=people,o=bms.com', search_filter=search_filter, search_scope=SUBTREE, attributes=["uid"])
        if con.entries:
            return con.entries[0].entry_dn
        else:
            return None

def cn_to_bmsid(old_cn):
    # if in the form CN=... get the uid
    # else return the current value (assumes it is a uid)
    # example format: CN=Holzhauer, Brian (00087387),OU=BMS Users,DC=one,DC=ads,DC=bms,DC=com	
    # return bmsid and uid for this record
    if old_cn == None:
        return None
    if old_cn.lower().startswith('CN'):
        # find parenthesis
        pos1 = old_cn.find('(')
        pos2 = old_cn.find(')',pos1 + 1)
        if (pos1 < 1) or (pos2 < 1):
            print("ERROR cn_to_bmsid did not find both parenthesis")
            return None
            bmsid = old_cn[pos1:pos2]
            uid = bmsid_to_uid(bmsid)
            return bmsid, uid
    else:
        uid = old_cn
        bmsid = uid_to_bmsid(uid)
        return bmsid, uid

def uid_to_bmsid(uid):
    with getED() as con:
        search_filter = f'(uid={uid})'
        search(con, search_base='ou=people,o=bms.com', search_filter=search_filter, search_scope=SUBTREE, attributes=["bmsid"])
        if con.entries:
            entry = con.entries[0]
            bmsid = getv(entry, 'bmsid')
            if type(bmsid) == list:
                bmsid = bmsid[0]
            return bmsid
        else:
            return None 

def bmsid_to_uid(bmsid):
    with getED() as con:
        search_filter = f'(bmsid={bmsid})'
        search(con, search_base='ou=people,o=bms.com', search_filter=search_filter, search_scope=SUBTREE, attributes=["uid"])
        if con.entries:
            entry = con.entries[0]
            uid = getv(entry, 'uid')
            return uid
        else:
            return None 


class ad_data:
    manager_uid = ''
    secretary_uid = ''
    manager_bmsid = ''
    secretary_bmsid = ''
    description = ''
    tier = ''

def get_owners_for_ad(dn):
    # get bmsprivtier, manager, secretary, bmsadapprover, description
    # manager and secretary are in form CN= or they are uid's
    # bmsadapprover is a bmsid
    ad_rec = ad_data()
    records = getADNonpeople(env='prod', search_dn=dn)
    if 'description' in records[0]:
        ad_rec.description = records[0]['description'][0]
    if 'tier' in records[0] and len(records[0]['tier']) > 0:
        ad_rec.tier = records[0]['tier'][0]
    if 'bmsadapprover' in records[0] and len(records[0]['bmsadapprover']) > 0:
        ad_rec.manager_bmsid = records[0]['bmsadapprover'][0] 
        ad_rec.manager_uid = bmid_to_uid(ad_rec.manager_bmsid)
        if len(records[0]['bmsadapprover']) > 0:
            ad_rec.secretary_bmsid = records[0]['bmsadapprover'][1]
            ad_rec.secretary_uid = bmid_to_uid(ad_rec.secretary_bmsid)
    elif 'manager' in records[0]:
        ad_rec.manager_bmsid, ad_rec.mananger_uid = cn_to_bmsid(records[0]['manager'][0])
        if 'secretary' in records[0]:
            ad_rec.secretary_bmsid, ad_rec.secretary_uid = cn_to_bmsid(records[0]['secretary'][0])
    return ad_rec

def update_ad_fields(field, newValue, dn):
    print(f"update_ad_fields {field} {newValue}, {dn}")
    ret = updateLdapServerValue('AD', dn, field, newValue)
    if ret == False:
        return False
    return True # just test we get here in debugger for now

def update_ad_owner(field, new_value, dn):
    '''
      Strategy:
        1) Read bmsprivtier, manager, secretary, bmsassignedowners, description from AD LDAP sing dn given
        2) If changing tier, change it's value if valid
        3) Do not allow description change
        4) If changing manager or secretary:
          a) Get current manager, secretary uid and bmsid's
             either from manager, secratary, bmsassignedowners or desciption
          b) determine if mananger of secretary was changed
          c) write back to bmsassignedowners the new mananger/secretary combo
          d) write to description with an upate on (Owners uid1 & uid2)
    '''
    if field.lower() == 'descripiton':
        print(f"Error - updateRecord cannot update description in AD")
        appLog.error(f"Error - updateRecord cannot update description in AD")
        return False
    if field.lower() == 'tier':
        valid_values = '012345'
        if new_value not in valid_values:
            print(f"Error - updateRecord cannot update tier to value {new_value} in AD")
            appLog.error(f"Error - updateRecord cannot update tier to value {new_value} in AD")
            return False
    if field.lower() not in ['manager','secretary']:
        print(f"Error - updateRecord cannot update {field} in AD")
        appLog.error(f"Error - updateRecord cannot update {field} in AD")
        return False
    ad_info = get_owners_for_ad(dn)
    # determine if manager or secreatry
    if field == 'manager' and ad_info.manager_uid != new_value:
        print(f'changing manager from {ad_info.manager_uid} to {new_value}')
        new_owners = [uid_to_bmsid(new_value)]
        uid_pair = [new_value]
        # see if there is a secretary
        if ad_info.secretary_bmsid != '':
            print(f'setting secretary to {ad_info.secretary_uid}')
            new_owners.append(ad_info.secretary_bmsid)
            uid_pair = [new_value, ad_info.secretary_uid]
    elif ad_info.secretary_uid != new_value:
        print(f'changing secretary from {ad_info.secretary_uid} to {new_value}')
        new_owners = [ad_info.manager_bmsid, uid_to_bmsid(new_value)]
        uid_pair = [ad_info.mananger_uid, new_value]
    else:
        print(f"Error - updasteRecord did not detect change in owner for AD")
        appLog.error(f"Error - updasteRecord did not detect change in owner for AD")
        return False
    
    # now ready to make the change

    # do we need to edit old description?
    uid_pair =  " & ".join(uid_pair) + ")"
    old_description = ad_info.description
    if 'owners' in old_description.lower():
        pos1 = old_description.lower().find('owners')
        pos2 = old_description.find(')',pos1 + 7)
        new_description = old_description[:pos1+8] + uid_pair + old_description[pos2+1:]
    else: # make a new description
        new_description = f"Owners {uid_pair}"
    # make the updates 
    ret1 = update_ad_fields('bmsadapprover',new_owners,dn)
    ret2 = update_ad_fields('description',new_description,dn)
    if ret1 == False or ret2 == False:
        return False
    # as before, we will update the change_log for this entry 
    return True, new_description

def updateLdapServerValue(source, dn, field, newValue):
    if field == 'tier':
        field = 'bmsprivtier'
    if source.lower() == 'ed': # deta read from fr has been re-labled ed
        con = getFR_NPA()
    if source.lower() == 'am':
        con = getAM_NPA()
    if source.lower() == 'ad':
        con = getAD()
    if not con:
        print(f'ERORR - cannot connect to {source} server!')
        appLog.error(f'updateRecord - cannot connect to {source} server!')
        return False
    # modifiying 2 values, delete both, add eac seprately
    if type(newValue) == list:
        con.modify(dn, {field: [(MODIFY_REPLACE, [newValue[0]])]})
        con.modify(dn, {field: [(MODIFY_ADD, [newValue[1]])]})
    else:
        con.modify(dn, {field: [(MODIFY_REPLACE, [newValue])]})
    if con.result['description'] == 'success':
        appLog.info(f'updateRecord - Successfully updated {field} to {newValue} in {source} for {dn}')
        print(f'updateRecord - Successfully updated {field} to {newValue} in {source} for {dn}')
    else:
        appLog.error(f'updateRecord - Failed to update {field} in {source} for {dn}: {con.result["description"]}')
        print(f'ERROR updateRecord - could not update record in {source} : {con.result["description"]}')
        return False
    return True # everything good

def updateRecord(user, uid, source, field, newValue):
    #appLog.info("in update function")
    # Rules:
    # we do not update, AM.  
    # when we update FR, we update AM as well
    # currently don''t have access to update ED
    # currently don't have access to update AD

    sql = ''
    originalValue = newValue
    print(f'*** updateRecord {uid} {source} {field} {newValue} ***')
    if not uid:
        appLog.error("You need a UID for updateRecord")
        print("ERROR - You need a UID for updateRecord")
        return False

    #good_sources = ['ad','ed','fr','am']
    # good_sources = ['fr','ad'] # to change when we have ED and AD access
    good_sources = ['ed','ad'] # WE changed FR name to ED in sql database 8/6/2024
    if not source or source.lower() not in good_sources:
        appLog.error(f"Invalid source {source} for updateRecord")
        print(f"ERROR Invalid source {source} for updateRecord")
        return False


    valid_fields = ['manager', 'secretary', 'tier']
    valid_fields_ad = ['manager', 'secretary']
    if source.lower() in ['ed','ad']: # no longer reading ed, fr is relabeld to ed
        if field not in valid_fields:
            # appLog.error(f"Invalid field: {field}")
            print(f'ERR invalid field {field} for updateRecord')
            return False
    
    # if field is manager or secretary, get the dn for this person
    # if not found, report error 
    if field in ['manager','secretary']:
        person_dn = get_user_dn(newValue)
        if not person_dn:
            print(f'ERROR Could not find dn for {newValue}')
            appLog.error(f'updateRecord - could not find dn for {newValue}')
            return False
        else:
            newValue = person_dn # this will be written to db

    # validate tier value:
    if field == 'tier':
        # remove spaces from tier
        newValue = newValue.replace(' ','')
        if newValue not in ['0','1','2','3']:
            print(f'ERROR Invalid value{newValue} for tier')
            appLog.error(f'updateRecord - Invalid value{newValue} for tier')
            return False
            
    try:
    #while True:
        # 1) look up in mysql using source and uid
        # 1a) make sure we get only 1 record
        # 2) then update LDAP FR or AD
        # 3) add to audit table, user, the change and date
        # 4) finally, update mysql nonpeople_entries table

        # 1) look up in mysql using source and uid, and make sure we get only 1 record
        sql = f"SELECT dn,description FROM nonpeople_entries WHERE uid = '{uid}' AND SOURCE = '{source}'"
        records = executeQuery(sql,[])
        if len(records) != 1:
            print('ERR did not get exactly 1 record for UpdateRecord') 
            appLog.info(f"Update record did not find 1 record")
            return False
        dn = records[0]['dn']
        dn_unmodified = dn
        dn = dn.replace(' ','') # remove spaces
        description = records[0]['description']
        # 2) Save to LDAP
        # manager and secretary need to be in the form:
        # bmsid=00614869,ou=People,o=bms.com
 
        if (source.lower() == 'ed') or (field == 'tier'):
            if source.lower() == 'ad':
                ret = updateLdapServerValue(source.lower(), dn_unmodified, field, newValue)
            else:
                ret = updateLdapServerValue(source.lower(), dn, field, newValue)
            if not ret:
                return ret
            # also upate AM if not tier
            if field != 'tier':
                ret = updateLdapServerValue('am', dn, field, originalValue)
                if not ret:
                    return ret
        elif source.lower() == 'ad':
            ret,new_description = update_ad_owner(field, originalValue, dn_unmodified)
            if ret == False:
                return False
        else:
            print('ERR invalid source for UpdateRecord') 
            appLog.info(f"Update record - Invalid source")
            return False
        
       
        # 3) add to audit table, user, the change and date
        sql = f"INSERT INTO change_log (date, editor_uid, npa_uid, destination, field_changed, value_changed) VALUES (DEFAULT, '{user}', '{uid}', '{source.upper()}', '{field}', '{newValue}')"
        con = getNPADatabase()
        cur = con.cursor()
        cur.execute(sql, [])
        if cur.rowcount == 0:
            appLog.info(f"ERROR Could not save to change_log due to SQL error")
            print(f"ERR updateRecord - could not save to change_log SQL {sql}")
            con.close()
            return False
        con.commit()
        # if updating FR, also tell audit table we updated AM
        if source.lower() == 'ed':
            sql = f"INSERT INTO change_log (date, editor_uid, npa_uid, destination, field_changed, value_changed) VALUES (DEFAULT, '{user}', '{uid}', 'AM', '{field}', '{newValue}')"
            con = getNPADatabase()
            cur = con.cursor()
            cur.execute(sql, [])
            if cur.rowcount == 0:
                appLog.info(f"ERROR Could not save ED source value to change_log")
                print("ERR updateRecord - could not save ED source value to change_log")
                con.close()
                return False
            con.commit()

        # 4) finally, update mysql nonpeople_entries table
        newValue = originalValue # do not use dn, use uid
        con = getNPADatabase()
        cur = con.cursor()
        sql = f"UPDATE nonpeople_entries SET {field} = '{newValue}' WHERE uid = '{uid}' and source = '{source}'"
        cur.execute(sql, [])
        con.commit()
        # if updating AD, also save new description
        if (source.lower() == 'ad') and (field != 'tier'):
            sql = f"UPDATE nonpeople_entries SET description = '{new_description}' WHERE uid = '{uid}' and source = '{source}'"
            cur.execute(sql, [])
        #if cur.rowcount == 0:
        #    appLog.info(f"No record updated for UID: {uid}.")
        #    print(f"ERR could not update record in mysql {sql}")
        #    con.close()
        #    return False
        con.commit()
        con.close()
        appLog.info(f"Record updated successfully: {uid}, {field} set to {newValue}")
        return True

    except Exception as e:
        appLog.error(f"Error updating record: {e}")
        print(f"ERROR updating record: {e} {sql}")
        return False
                                        
def convert_bmsid_to_uid(update_field):

    # # make a list of users in dn form
    # sql = f"select distinct {update_field} from nonpeople_entries where {update_field} like '%bmsid=%'"
    # records = executeQuery(sql, [])
    # dns = [entry[update_field] for entry in records]
  
    # # now get the uid's for these dns 
    # dn_uid_mapping = {}
    # with getED() as con:
    #     for dn in dns:
    #         dn_split = dn.split(',')
    #         search_filter = f"({dn_split[0]})"
    #         search(con, search_base='o=bms.com', search_filter=search_filter, search_scope=SUBTREE, attributes=["uid"])
    #         if con.entries:
    #             uid = str(con.entries[0]['uid'])
    #             dn_uid_mapping[dn] = uid
		
    # # use this mapping to update the db
    # print(f'{update_field}: updating {len(dn_uid_mapping.keys())} records in db') 

    # '''
    #     con = getNPADatabase()
    #     cur = con.cursor()

    #     sql = f"UPDATE nonpeople_entries SET {field} = %s WHERE uid = %s and source = %s"
    #     print(f'sql {sql} params {(newValue, uid, source)}')
    #     cur.execute(sql, (newValue, uid, source))
    #     if cur.rowcount == 0:    
    # '''
    # # copy existing dn to new field, so we can comare later
    # # only necessary for FR that saves dn, not uid for manager/secretary
    # con = getNPADatabase()
    # for dn in dn_uid_mapping.keys():
    #     cur = con.cursor()
    #     sql = f"UPDATE nonpeople_entries SET {update_field} = '{dn_uid_mapping[dn]}' WHERE {update_field} = '{dn}'"
    #     #res = executeQuery(sql, [])
    #     cur.execute(sql, [])
    #     if cur.rowcount == 0:
    #         print(f"ERROR executing {sql}")
    #         exit(1)
    #     con.commit()
    #     # success, continue
    #     # print(f'SUCCESS updated: {cur.rowcount}')
    #     print('.',end='')
    # print('done')

    # need to find entrys in uid format and get dn format
    # forge rock only
    update_dn_field = update_field + '_dn'
    sql = f"select DISTINCT {update_field} from nonpeople_entries where {update_field} IS NOT NULL AND {update_dn_field} IS NULL and source = 'ed';"
    records = executeQuery(sql, [])
    uids = [entry[update_field] for entry in records if entry[update_field].startswith('bmsid=') != True]
    # get the bmsid's
    print(f"convert_bmsid_to_uid need to find {len(uids)} bmsids")
    # now get the uid's for these dns 
    uid_dn_mapping = {}
    with getED() as con:
        for uid in uids:
            search_filter = f"(uid={uid})"
            search(con, search_base='o=bms.com', search_filter=search_filter, search_scope=SUBTREE, attributes=["bmsid"])
            if con.entries:
                bmsid = str(con.entries[0].entry_dn)
                uid_dn_mapping[uid] = bmsid
    # update mysqldb with bmsids found
    con = getNPADatabase()
    cur = con.cursor()
    for uid in uid_dn_mapping:
        bmsid = uid_dn_mapping[uid]
        source = 'ed'
        sql = f"UPDATE nonpeople_entries SET {update_dn_field}"
        sql += f" = '{bmsid}'"
        sql += f" WHERE source = 'ed' and {update_field} = '{uid}'"
        cur.execute(sql, [])
        if cur.rowcount == 0:
            print(f"ERROR executing {sql}")
            exit(1)
        con.commit()
        print('.',end='')
    print('done')

def fix_dns():
    # some manager and secretary fields are in format bmsid=1234567,....
    # convert to uid format
    appLog.info("fix_dns")
    convert_bmsid_to_uid('manager')
    convert_bmsid_to_uid('secretary')

def create_source_uid_dict(data):
    # put accounts in a dict, with key = combination of source and uid
    # data is a dict of npa accounts put into new dict keyed by source_uid field 
    source_uid_data = {}
    for entry in data:
        try:
            if not entry['uid']: # use cn instead
                if type(entry['cn']) == list:
                    source_uid = entry['source'] + '_' + entry['cn'][0]
                else:
                    source_uid = entry['source'] + '_' + entry['cn']
            else:
                if type(entry['uid']) == list:
                    source_uid = entry['source'] + '_' + entry['uid'][0]
                else:
                    source_uid = entry['source'] + '_' + entry['uid']
            source_uid_data[source_uid] = entry
        except Exception as e:
            print(f'create source_id error ',str(e))
    return source_uid_data

def load_mysql_table(table_name):
    print('load_mysql_table')
    # return all records from given table 
    sql = f'SELECT * FROM {table_name}'
    # sql = f"SELECT * FROM {table_name} WHERE source = 'ad'"
    records = executeQuery(sql, [])
    return records

def get_fr_manager_or_secretary(entry, process_manager=True):
    # check field is present
    # check format of field: uid or dn
    # return dn format if possible
    if process_manager:
        field = 'manager'
    else:
        field = 'secretary'
    dn_field = field + '_dn'
    if entry[field] == None:
        return None
    if entry[field].startswith('bmsid'):
        return entry[field]
    if entry[dn_field] == None:
        return None
    return entry[dn_field]


def compare_npas(ldap_npa, mysql_npa):
    compares = ['cn', 'description', 'dn', 
  'manager', 'secretary', 'source', 'uid' ]
    for c in compares:
        ldap_item = ldap_npa[c]
        # for fr, mananager and secretary fields need to compare to dns
        if mysql_npa['source'] == 'ed':
            if c == 'manager':
                mysql_item = get_fr_manager_or_secretary(mysql_npa, True)    
            elif c == 'secretary':
                mysql_item = get_fr_manager_or_secretary(mysql_npa, False)    
            else:
                mysql_item = mysql_npa[c]
        else:      
            mysql_item = mysql_npa[c]
        # check for missing attribute
        if (not ldap_item or ldap_item == ['']) and (not mysql_item ):
            continue
        if not mysql_item:
            return False  # ldap has attribute, mysql is missing it
        if type(ldap_item) == list:
            if ldap_item == []:
                ldap_item = ''
            else:
                ldap_item = ldap_item[0]
        if c == 'description': # check for capitalization
            # if both are white space, then they are equal
            if ldap_item.replace(" ","") == mysql_item.replace(" ",""):
                continue
            if ldap_item != mysql_item:
                return False
        else: # don't check capitalization, FIX SPACES
            ldap_item = ldap_item.replace(" ","")
            mysql_item = mysql_item.replace(" ","")
            if ldap_item.lower() != mysql_item.lower():
                return False 
    # all match 
    return True

def compare_tables(ldap_dict, mysql_dict):
    # determine changes in accounts
    changed_dict = {}
    # use sets for comparision
    ldap_set = {key for key,value in ldap_dict.items()}
    mysql_set = {key for key,value in mysql_dict.items() if (not key.startswith('manual')) and (not key.startswith('other'))}
    deleted = mysql_set - ldap_set
    added = ldap_set - mysql_set
    # determined entries that have changed
    changed = set()
    intersected = ldap_set.intersection(mysql_set)
    for item in intersected:
        if compare_npas(ldap_dict[item], mysql_dict[item]) == False:
            changed.add(item)
    appLog.info(f"to delete: {len(deleted)} add: {len(added)} change: {len(changed)}")
    return deleted, added, changed

def delete_from_mysql(mysql_dict, deleted):
    # mysql_dict keyed on source_uid, delete is a set of items to delte
    # each deleted entry in form source_uid
    if not deleted:
        return
    con = getNPADatabase()  
    cur = con.cursor()
    for d in deleted:
        d_split = d.split('_')
        source = "'" + d_split[0] + "'"
        uid = "'" + d_split[1] + "'"
        sql = f'''DELETE FROM nonpeople_entries where SOURCE = {source} AND UID={uid}'''  
        cur.execute(sql, [])
        con.commit()
    con.close()
    cur.close()

def get_ldap_string(ldap_value):
    # handle none, empty list, list value, return string in quotes
    if type(ldap_value) == list:
        if ldap_value == []:
            value = "' '"
        else:
            value = "'" + ldap_value[0] + "'"
    elif ldap_value == None:
        value = "' '"
    else:
        value = "'" + ldap_value + "'"
    return value

def add_to_mysql(ldap_dict, added):
    if not added:
        return
    con = getNPADatabase()  
    cur = con.cursor()
    for a in added:
        excluded_fields = ['in_ad','last_source', 'in_ed', 'in_am', 'in_fr', 'in_ad ']
        fields = []
        values = []
        # fix for tier = []
        if ('tier' in ldap_dict[a]) and \
          (type(ldap_dict[a]['tier']) == list) and \
          (ldap_dict[a]['tier']==[]):
            excluded_fields.append('tier') # only this time

        for k,v in ldap_dict[a].items():
            if k not in excluded_fields:  # fields in_fr, in_am ..
                fields.append(k)
                value = get_ldap_string(v)
                values.append(value)
        s_fields = ','.join(fields)
        s_values = ','.join(values)
        sql = f"INSERT INTO nonpeople_entries ({s_fields})"
        sql += f" VALUES ({s_values})" 
        try:
            pass
            #cur.execute(sql, [])
            #con.commit()
        except Exception as e:
            print('ERROR adding record ', str(e))
            print('sql: ',sql)
    con.close()
    cur.close()

def process_mysql_changes(ldap_dict, changed):
    if not changed:
        return
    con = getNPADatabase()  
    cur = con.cursor()
    for c in changed:
        excluded_fields = ['in_ad','last_source', 'in_ed', 'in_am', 'in_fr', 'in_ad ','source','uid']
        # fix for tier = []
        if ('tier' in ldap_dict[c]) and \
          (type(ldap_dict[c]['tier']) == list) and \
          (ldap_dict[c]['tier']==[]):
            excluded_fields.append('tier') # only this time

        set_list = [] # hold each set = x token
        for k,v in ldap_dict[c].items():
            if k not in excluded_fields:  # fields in_fr, in_am ..
                value = get_ldap_string(v)
                s = f'{k} = {value}'
                set_list.append(s)
        set_string = ', '.join(set_list)
        source = ldap_dict[c]['source']
        uid = get_ldap_string(ldap_dict[c]['uid'])
        # UPDATE table_name SET column1 = value1, column2 = value2, ...WHERE condition;
        sql = f"UPDATE nonpeople_entries SET {set_string}"
        sql += f" WHERE source = '{source}'"
        sql += f" AND uid = {uid}"
        try:
            cur.execute(sql, [])
            con.commit()
        except Exception as e:
            print('ERROR changing record ', str(e))
            print('sql: ',sql)
    con.close()
    cur.close()
        
def synch_mysql_ldap():
    '''
    1) Get all npa accounts from ldap
    2) put accounts in a dict, with key = combination of source and uid
    3) Get all accounts from mysql table nonpeople_entries
    4) put accounts in a dict, with key = combination of source and uid
    5) determine change in accounts:
       IGNORE accounts with source = "manual" or "other"
        a) deleted (in mysql, not in ldap)
        b) added (in ldap, not in mysql)
        c) changed (in both, but data is different)
    6) Removed deleted accounts from mysql 
    7) Update changed accounts from mysql
    8) Make a LIST of added accounts - to determine how to register these (they should all be manual/other source)    
    '''
    appLog.info("synch_mysql_ldap")
    #  Get all npa accounts from ldap
    ldap_accounts = getAllNonpeople()
    # put into source_uid dict
    ldap_dict = create_source_uid_dict(ldap_accounts)
    # Get all accounts from mysql table nonpeople_entries
    mysql_accounts = load_mysql_table('nonpeople_entries')
    # put into source_uid dict
    mysql_dict = create_source_uid_dict(mysql_accounts)
    # determine changes in accounts
    deleted, added, changed = compare_tables(ldap_dict, mysql_dict)
    # handle deletions to myql
    delete_from_mysql(mysql_dict, deleted)
    # handle additions to myql
    add_to_mysql(ldap_dict, added)
    # handle changes
    process_mysql_changes(ldap_dict, changed)
    # convert manager and secretary to uid format
    fix_dns()

# Check if a string is in a list, regardless of case.
def inCaseless(string, iterable):
    if string is None or iterable is None:
        return False
    return string.lower() in (s.lower() for s in iterable)

def isUserInGroup(groupCN, userUID):
    print(f"isUserInGroup {groupCN} {userUID}")
    with getED() as dsCon:
        entries = search(dsCon, search_base=f'cn={groupCN},ou=groups,o=bms.com', search_filter='(objectClass=*)', search_scope=BASE, attributes=['uniqueMember'])
        if entries:
            if entries[0] and entries[0]['attributes'] and entries[0]['attributes']['uniqueMember']:
                members = entries[0]['attributes']['uniqueMember']
                dn = get_user_dn(userUID)
                return inCaseless(dn, members)
        return False   

def fix_tier_nulls():
    print('fix_tier_nulls... loading data')
    ldap_accounts = getAllNonpeople()
    uids = []
    for l in ldap_accounts:
        if l['tier'] == [] and l['uid'] != []:
            uids.append(l['uid'])
    print(f"found {len(uids)} uids from {len(ldap_accounts)} accounts")
    print(uids[0:2])
    # update the db
    # batches of 100
    # check for non list
    for u in uids:
        if type(u) != list:
            print(u,type(u))
            exit(0)
    batch_start = 0
    con = getNPADatabase()
    cur = con.cursor()
    while True:
        try:
            print('.', end='', flush=True)
            uid_batch = [x[0] for x in uids[batch_start:batch_start+100]]
            search_uids = '("' + '","'.join(uid_batch) + '")'   
            #print(search_uids)
            #exit(0)
            sql = f"UPDATE nonpeople_entries SET tier = NULL WHERE uid in {search_uids}"
            cur.execute(sql, [])
            con.commit()
            if batch_start + 100 >= len(uids):
                break
            batch_start += 100
        except:
            print("ERR with ", batch_start)
            exit(0)
    print()





# From Command Line: python3 nonPeople.py <function_name>
#  Examples:
# to synch ldap nonpeople: python3 nonPeople.py synch_mysql_ldap
# to synch cyberark: python3 nonPeople.py synch_cyberark
if __name__ == '__main__':
    globals()[sys.argv[1]]()

#if __name__ == "__main__":
    # synch_mysql_ldap()
    #synch_cyberark()
    ## others ##
    #fix_tier_nulls()
    #searchCyberark('', {}, start=0, length=100, sort_column=0, sort_direction='asc', sources=None, fields=None)
    #searchColFilter(query='', col_filter={}, start=0, length=10, sort_column=0, sort_direction='asc', sources=None, fields=['uid', 'cn', 'source', 'tier', 'manager', 'secretary', 'description'], user='samuell3')	    
    #searchCaTest('',{})
    #clean_ca_entries()
    #load_ca_to_mysql()
    #load_managar_or_secretary_dns_to_mysql(True)
    #load_managar_or_secretary_dns_to_mysql(False)
    #fix_dns()
    #reloadNPADatabase()
    #updateRecord('polyanss', 'dash', 'ED', 'tier', '1')
    #updateRecord('samuell3', 'APP_JOINENGINE2', 'AD', 'tier', '2')
    #updateRecord('samuell3', 'APP_PSYNC2', 'AD', 'secretary', 'orcutte')
    #searchCaTest('', col_filter={}, start=0, length=100, sort_column=0, sort_direction='asc', sources=None, fields=None)
    #n = lookup_people('doug w')
    #print(n)
    #ownerAltOwnerReport()
    #get_change_log('U', start=0, length=100, sort_column=0, sort_direction='asc')
    #getCANonpeople()
    #reloadNPADatabase()
    #test_cyberark()
             
