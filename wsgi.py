#!/usr/bin/python3
import sys
import os
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.append(BASE_DIR)
sys.path.append('/idm/ldap/.local/bin')
sys.path.append('/usr/local/bin')
sys.stdout = sys.stderr
from app import app


application = app
