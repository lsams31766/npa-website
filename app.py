#!/usr/bin/python3
import sys
import logging as l
from functools import wraps
from io import StringIO
import pandas as pd
import os
sys.path.append('/idm/ldap/.local/bin/')
sys.path.append('/usr/local/bin/')
sys.path.append('/usr/lib64/')

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

DEFAULT_USER = 'bridgerz'
APP_LOG_PATH = os.path.join(BASE_DIR, 'logs', 'app.log')
LOG_LEVEL = l.INFO

# get_safe_sizes() # store sizes of safes, so we can calcualte filtered records

def setupLogger(name, logFile, formatter, level=LOG_LEVEL):
    handler = l.FileHandler(logFile)
    handler.setFormatter(formatter)
    logger = l.getLogger(name)
    logger.setLevel(level)
    logger.addHandler(handler)
    return logger

appLog = setupLogger('appInfo', APP_LOG_PATH, l.Formatter('%(asctime)s: %(levelname)s: %(message)s', datefmt="%Y-%m-%d %H:%M:%S"))


from flask import Flask, render_template, request, jsonify, url_for, redirect, g, abort, send_file, Response
import traceback

app = Flask(__name__)

import nonPeople as np

@app.before_request
def auth():
    g.user = str(request.headers.get('Smuid'))

@app.after_request
def disallowCache(response):
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, proxy-revalidate"
    response.headers["Pragma"] = "no-cache"
    response.headers['Expires'] = "0"
    return response

def isAllowedModification(uid):
    if uid == None or uid.lower() == 'none':
        uid = 'samuell3'
    for group in ["SG-ACCSVN", "MG-AUTH-SERVICES"]:
        appLog.info(group + ":" + uid)
        if np.isUserInGroup(group, uid):
            appLog.info("he's in!")
            return True
    return False

# Links needed on home page
link_IT_SOP_400='''https://purl.bms.com/bmsdocs/e/1462460.pdf'''

link_IT_WI_4014='''https://purl.bms.com/bmsdocs/e/1464541.pdf'''

link_CyberArkSafeCreation='''
https://bmsnprod.service-now.com/esc?id=sc_cat_item&table=sc_cat_item&sys_id=b9e882b41b9c2c5089bbc5d96e4bcb1d'''

link_CyberArkAccountOnboarding='''
https://bmsnprod.service-now.com/esc?id=sc_cat_item&table=sc_cat_item&sys_id=7c9078ec1b14645089bbc5d96e4bcb9e'''

link_OneDomainApplication='''https://bmsnprod.service-now.com/esc?id=ep_sc_cat_item&table=sc_cat_item&sys_id=f00d4056dbf51050fd76b2a2ba961978&recordUrl=com.glideapp.servicecatalog_cat_item_view.do%3Fv%3D1&sysparm_id=f00d4056dbf51050fd76b2a2ba961978'''

link_NonPeopleLdapAccount='''https://bmsnprod.service-now.com/esc?id=ep_sc_cat_item&table=sc_cat_item&sys_id=acf82961473c2d90e72d7116536d43ff'''

link_CybearArkGeneralRequest= '''https://bmsnprod.service-now.com/esc?id=sc_cat_item&table=sc_cat_item&sys_id=d1119c88db6f501067e97d84f39619b3'''

link_CyberArkAccessToActiveDirectoryGroup = '''https://bmsnprod.service-now.com/esc?id=sc_cat_item&table=sc_cat_item&sys_id=1c36b989dbdfd81067e97d84f3961943'''

links = {
    '0':link_IT_SOP_400, 
    '1':link_IT_WI_4014,
    '2':link_CyberArkSafeCreation,
    '3':link_CyberArkAccountOnboarding,
    '4':link_OneDomainApplication,
    '5':link_NonPeopleLdapAccount,
    '6':link_CybearArkGeneralRequest,
    '7':link_CyberArkAccessToActiveDirectoryGroup
}

    
@app.route('/', methods=['GET'])
def index():
    print("### index ###")
    return render_template('nonPeople.html', activePage='index', showChangeLogLink=isAllowedModification(g.user), links=links)

@app.route('/all', methods=['GET'])
def all():
    print("### all ###")
    return render_template('all.html', activePage='all')

@app.route('/cyberark', methods=['GET'])
def cyberark():
    print("### cyberark ###")
    return render_template('cyberark.html', activePage='cyberark')

@app.route('/my', methods=['GET'])
def my():
    print("### my ###")
    return render_template('my.html', activePage='my')

@app.route('/changeLog', methods=['GET'])
def changeLog():
    print("### changelog ###")
    return render_template('change_log.html', activePage='change_log')

def sanitize(input_string, remove_trailing_space=True):
    # remove leading spaces from input string
    # also only allow alphanumeric characters - to prevent sql injection
    allowed = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789- _=@/\$#%().,'
    s = input_string.lstrip()
    if remove_trailing_space == True:
        s = s.rstrip()
    # only permit allowed characters
    t = ''
    for letter in s:
        #if letter in allowed:
        t += letter
    return t    

def get_datatable_fields(request_value):
    ''' format is [('draw', '1'),
    ('columns[0][data]', 'user_name'), 
    ('columns[0][name]', ''), 
    ('columns[0][searchable]','true'), 
    ('columns[0][orderable]', 'true'), 
    ('columns[0][search][value]', ''), 
    ('columns[0][search][regex]', 'false'), 
    ('columns[1][data]', 'tier'), ...
    '''
    fields = [value for key,value in request_value.items() if '[data]' in key]
    return fields
        
@app.route('/update', methods=['POST'])
def updateNPA():
    print("### updateNPA ###")
    
    data = request.json
    print(f"data {data}")
    uid = data.get('uid')
    field = data.get('field')
    newValue = data.get('newValue')
    source = data.get('source')
    user = g.user
    # only for local testing
    if (not user) or (user.lower() == 'none'):
        #user = 'samuell3'
        user = 'polyanss'
    print(f"user {user} uid {uid} source {source} field {field} newValue {newValue}")
    # while True:
    try:
        #appLog.info("trying")
        print('updateNPA',user, uid, source, field, newValue)
        success = np.updateRecord(user, uid, source, field, newValue)
        #appLog.info('update function ran')
        if success:
            return jsonify({"success": True, "message": "Record updated successfully"}), 200
        else:
            return jsonify({"success": False, "message": "Failed to update record"}), 500
    except Exception as e:
        appLog.info("update error: ", str(e))
        return jsonify({"success": False, "message": str(e)}), 500

@app.route('/col_filter_test', methods=['GET'])
def col_filter_test():
    return render_template('col_filter.html')

@app.route('/ca_test', methods=['GET'])
def ca_test():
    return render_template('test_ca.html')

@app.route('/test_find_person', methods=['GET'])
def test_find_person():
    return render_template('test_find_person.html')   

def doColFilter(filter_user=False): # // common function for all and my web pages
    try:
        print("*** doColFilter *****")
        draw = request.args.get('draw', type=int, default=1)
        start = request.args.get('start', type=int, default=0)
        length = request.args.get('length', type=int, default=10)
        search_value = request.args.get('search[value]', default='')

        sort_column_index = int(request.args.get('order[0][column]', default=0))
        sort_direction = request.args.get('order[0][dir]', default='asc')
        column_filter = {}
        # get all search colulmn
        fields = get_datatable_fields(request.args)
        if filter_user:
            user = g.user
            # only for local testing
            if (not user) or (user.lower() == 'none'):
                #user = 'samuell3'
                user = 'polyanss'
            appLog.info('myData: user ' + str(user))
        else:
            user = None # do not filter on user
        # print(fields)
        # get all search colums
        i = 0
        for key,value in request.args.items():
            v = sanitize(value)
            if ('[search][value]' in key):
                if v !=  '':
                    if fields[i] == 'description':
                        column_filter[i] = sanitize(value, remove_trailing_space=True)
                    else:
                        column_filter[i] = v
                i += 1
        #print("column_filter",column_filter)
        #print("search_value",search_value)
        #print("**************")
        search_value = sanitize(search_value)
        search_results = np.searchColFilter(fields=fields, query=search_value, col_filter=column_filter, start=start, length=length, 
                                          sort_column=sort_column_index, sort_direction=sort_direction, user=user)
        #print('**** search results *****', search_results)
        return jsonify({
            "draw": draw,
            "recordsTotal": search_results['totalRecords'],
            "recordsFiltered": search_results['totalFilteredRecords'],
            "data": search_results['results']
        })
    except Exception as e:
      appLog.error(f"Error in /data/all: {e}")
      return jsonify({
          "draw": draw,
          "recordsTotal": 0,
          "recordsFiltered": 0,
          "data": []
      })


@app.route('/data/col_filter_test', methods=['GET'])
def colFilterTestData():
    return doColFilter()

@app.route('/data/my', methods=['GET'])
def myData():
   return doColFilter(filter_user=True)

@app.route('/data/cyberark', methods=['GET'])
def caData():
    try:
        #print("*** caData *****")
        draw = request.args.get('draw', type=int, default=1)
        start = request.args.get('start', type=int, default=0)
        length = request.args.get('length', type=int, default=10)
        search_value = request.args.get('search[value]', default='')

        sort_column_index = int(request.args.get('order[0][column]', default=0))
        sort_direction = request.args.get('order[0][dir]', default='asc')
        column_filter = {}
        fields = get_datatable_fields(request.args)
        # get all search colums
        i = 0
        for key,value in request.args.items():
            v = sanitize(value)
            if ('[search][value]' in key):
                if v !=  '':
                    column_filter[i] = v
                i += 1
        print("column_filter",column_filter)
        #print("search_value",search_value)
        #print("**************")
        search_value = sanitize(search_value)
        search_results = np.searchCyberark(fields=fields, query=search_value, col_filter=column_filter, start=start, length=length, 
                                          sort_column=sort_column_index, sort_direction=sort_direction)
        # print('**** search results *****', search_results)

        return jsonify({
            "draw": draw,
            "recordsTotal": search_results['totalRecords'],
            "recordsFiltered": search_results['totalFilteredRecords'],
            "data": search_results['results']
        })
    except Exception as e:
       appLog.error(f"Error in /data/ca_test: {e}")
       return jsonify({
           "draw": draw,
           "recordsTotal": 0,
           "recordsFiltered": 0,
           "data": []
       })

@app.route('/get_safe_details', methods=['POST'])
def get_safe_details():
    #print('GET SAFE DETAILS!!!')
    try:
    #if True:
        data = request.get_json()['data']
        print(f'data {data}')
        safe_id = data['safe_id']
        print(f'safe_id {safe_id}')
        policies, owners = np.get_ca_details(safe_id)
        print(f'got {policies} {owners}')

        return jsonify({
            "safe_id":data['safe_id'],
            "safe_name":data['safe_name'],
            "policies": policies,
            "owners": owners
        })
    except Exception as e:
        appLog.error(f"Error in /get_safe_details: {e}")
        print("ERROR getting details on safe")
        return jsonify({
             "safe_id":"?",
             "safe_name":"?",
             "policies": "?",
             "owners": "?"
        })

@app.route('/lookup_person', methods=['POST'])
def lookupPerson():
    print("### lookupPerson ###")
    data = request.json
    print(f"data {data}")
    entered_name = sanitize(data['data'].get('entered_name'))
    print(f"entered_name {entered_name}")
    try:
        #appLog.info("trying")
        # name_list = np.getNameList(entered_name)
        # we want First name, Last name, uid, site, association
        #name_list = [{"bmsuid": 1, "name": "Jane"}, {"id": 2, "name": "Sally"}, {"id": 3, "name": "Phil"}]
        name_list = np.lookup_people(entered_name)
        return jsonify({
            "name_list":name_list
        })
    except Exception as e:
        appLog.info("lookup_person error: ", str(e))
        return jsonify({"name_list":[]}), 500

@app.route('/getChangeLog', methods=['GET'])
def getChangeLog():
    print("### getChangeLog ###")
    try:
        draw = request.args.get('draw', type=int, default=1)
        start = request.args.get('start', type=int, default=0)
        length = request.args.get('length', type=int, default=100)
        search_value = request.args.get('search[value]', default='')
        sort_column_index = int(request.args.get('order[0][column]', default=0))
        sort_direction = request.args.get('order[0][dir]', default='asc')
        print(f"getChangeLog sort index {sort_column_index} direction {sort_direction}")
        #entrys = [
        #    {"date":"2024-05-07 01:02:03", "entry": "synch db"},
        #    {"date":"2024-06-06 02:03:04", "entry": "new description"},
        #]
        search_results = np.get_change_log(query=search_value, start=start, length=length, sort_column=sort_column_index, sort_direction=sort_direction)
        # print(f'getChangeLog entrys count {len(search_results)}')
        print(f"total {search_results['totalRecords']}")
        print(f"filtered {search_results['totalFilteredRecords']}")
        return jsonify({
            "draw": draw,
            "recordsTotal": search_results['totalRecords'],
            "recordsFiltered": search_results['totalFilteredRecords'],
            "data": search_results['results']
        })

    except Exception as e:
        print(f"change log error {e}")
        appLog.info("change log error: ", str(e))
        return jsonify({"data":[]}), 500

@app.errorhandler(500)
def handle500(error):
    traceback_str = traceback.format_exc()
    appLog.error(traceback_str)
    return f"Internal Server Error: {error}", 500


if __name__ == "__main__":
    app.debug = True
    appLog.info("LOADING!")
    app.run(host="0.0.0.0", port=8000, debug=True)
    #search_results = np.searchAllFull(query='', start=0, length=10, 
    #                                      sort_column=1, sort_direction='asc')
    #print(search_results)

