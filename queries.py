#queries.py
'''
  Generalized SQL queries to make searching simpler and global
'''
def get_col_filter_query(fields, col_filter, sort_column=0, sort_direction='asc', user=None,
        uid=None, dn=None, adn=None):
    # fields are the html table headers
    # col_folter is a dictionary relating number of field to filter text
    if user != None:
        user_filter = f"(manager IN ('{uid}', '{dn}', '{adn}') OR secretary IN ('{uid}', '{dn}', '{adn}'))"
    else:
        user_filter = ''
    like_fields = ["dn like '%'"] # we don't filter on dn
    for i in range(len(fields)):
        if i in col_filter.keys():
            s = f"{fields[i]} like '{col_filter[i]}%'"
            like_fields.append(s)
    like_statement = ' AND '.join(like_fields)
    if user != None:
        like_statement += ' AND ' + user_filter
    # print("*** searchColFilter like_statement",like_statement)
    #  order 1: if NULL, put at end 
    #  order 2: replace _ with space, so we can search _ entries
    all_records_count = 'SELECT COUNT(*) as total_records FROM nonpeople_entries'
    filtered_records_count = f'''SELECT COUNT(*) as filtered_records FROM nonpeople_entries 
   WHERE {like_statement}'''
    records = f'''SELECT * FROM nonpeople_entries
   WHERE {like_statement}
   ORDER BY CASE WHEN {fields[sort_column]} IS NULL THEN 2 ELSE 1 END, 
   REPLACE({fields[sort_column]}, '_', ' ') {sort_direction}
   LIMIT %s OFFSET %s'''
    print(all_records_count)
    print(filtered_records_count)
    print(records)
    return all_records_count, filtered_records_count, records

def get_general_search_query(fields, query, sort_column=0, sort_direction='asc'):
    # search on all fields for the query text
    query_lower = f"%{query.lower()}%"
    all_records_count = 'SELECT COUNT(*) as total_records FROM nonpeople_entries'
    filtered_records_count = '''SELECT COUNT(*) as filtered_records FROM nonpeople_entries 
   WHERE dn LIKE %s OR uid LIKE %s OR cn LIKE %s OR source LIKE %s 
   OR tier LIKE %s OR manager LIKE %s 
   OR secretary LIKE %s OR description LIKE %s'''
    records = f'''SELECT * FROM nonpeople_entries
   WHERE dn LIKE %s OR uid LIKE %s OR cn LIKE %s OR source LIKE %s 
   OR tier LIKE %s OR manager LIKE %s OR secretary LIKE %s 
   OR description LIKE %s 
   ORDER BY {fields[sort_column + 1]} {sort_direction}
   LIMIT %s OFFSET %s'''
    print(all_records_count)
    print(filtered_records_count)
    print(records)
    return all_records_count, filtered_records_count, records

def get_ca_search_query(fields, col_filter, sort_column=0, sort_direction='asc'):
    all_records_count = 'SELECT COUNT(*) as count FROM ca_name'
    #print('COL FILTER',col_filter)
    #print('SORT COLUMN',sort_column)
    #print('SORT DIRECTION',sort_direction)
    # like statement
    like_statement = '1=1'
    if col_filter:
        for key,value in col_filter.items():
            field_name = fields[key]
            field_value = f"'{value}%'"
            like_statement += f" AND {field_name} LIKE {field_value}"

    filtered_records_count = f'''SELECT COUNT(*) as count
                 FROM ca_name
                 WHERE {like_statement}'''
    records = f'''SELECT user_name, file_id, safe_id, address, safe_name, 
                 db, ci_id, tier 
                 FROM ca_name 
                 WHERE {like_statement}
                 ORDER BY REPLACE({fields[sort_column]}, '_', ' ') {sort_direction}
                 LIMIT %s OFFSET %s'''
    print(records)
    return all_records_count, filtered_records_count, records

def get_ca_policy_ids(safe_id):
    sql = f'''SELECT CAOPObjectPropertyValue FROM
     CyberArk.dbo.CAObjectProperties
     WHERE CAOPSafeId = {safe_id}'''
    sql += " AND CAOPObjectPropertyName = 'PolicyID'"
    return sql

def get_ca_owners(safe_id):
    sql = f'''SELECT CAOOwnerName FROM CyberArk.dbo.CAOwners
              WHERE CAOSafeID = {safe_id}'''
    return sql

def get_ca_safes_query(fields, col_filter):
    # like statement
    like_statement = '1=1'
    if col_filter:
        for key,value in col_filter.items():
            if fields[key] == 'address':
                alias = 'a'
            else:
                alias = 'n'
            field_name = fields[key]
            field_value = f"'{value}%'"
            like_statement += f" AND {alias}.{field_name} LIKE {field_value}"

    records = f'''SELECT n.safe_id 
                 FROM ca_name as n 
                 JOIN ca_address as a ON 
                 n.safe_id = a.safe_id
                 WHERE {like_statement}'''
    print(records)
    return records

def get_person_lookup_query_with_space(entered_name):
    if ' ' in entered_name:
        e_split = entered_name.split(" ")
        sql = f"""
        SELECT sn, cn, givenname, bmssite, bmssitecode, bmspersonassociation, bmsuid
        FROM people WHERE 
        mail IS NOT NULL
        AND bmspersonassociation != 'NONPEOPLE'
        AND 
        (
            (givenname like '{e_split[0]}%' and sn like '{e_split[1]}%')
            OR (sn like '{e_split[1]}%' and givenname like '{e_split[0]}%')
        )
        ORDER BY cn LIMIT 10;
        """
    print(sql)
    return sql


def get_person_lookup_query(entered_name):
    sql =f"""
    SELECT sn, cn, givenname, bmssite, bmssitecode, bmspersonassociation, bmsuid
    FROM people WHERE givenname like '{entered_name}%'
    OR sn like '{entered_name}%' 
    AND bmspersonassociation != 'NONPEOPLE'
    ORDER BY cn LIMIT 10
    """
    print(sql)
    return sql

def change_log_query(fields, query, sort_column=0, sort_direction='asc',limit=10,offset=0):
    # search on all fields for the query text
    query_lower = f"%{query.lower()}%"
    like_statement = '1=0'
    for f in fields:
            like_statement += f" OR {f} LIKE '{query_lower}'"
    all_records_count = 'SELECT COUNT(*) as total_records FROM change_log'
    filtered_records_count = f'''SELECT COUNT(*) as filtered_records FROM change_log 
    WHERE {like_statement} '''

 #   records = f'''SELECT date,entry FROM change_log
 #  WHERE date LIKE %s OR entry LIKE %s 
 #  ORDER BY {fields[sort_column + 1]} {sort_direction}
 #  LIMIT %s OFFSET %s'''
    if sort_column == 0:
        records = f'''SELECT date,editor_uid, npa_uid, destination, field_changed, value_changed FROM change_log
        WHERE {like_statement}
        ORDER BY STR_TO_DATE(date, '%Y-%m-%d %H:%i:%s') {sort_direction}
        LIMIT {limit} OFFSET {offset}'''
    else:
        records = f'''SELECT date,editor_uid, npa_uid, destination, field_changed, value_changed FROM change_log
        WHERE {like_statement}
        ORDER BY {fields[sort_column]} {sort_direction}
        LIMIT {limit} OFFSET {offset}'''

    print(records)
    return all_records_count, filtered_records_count, records
