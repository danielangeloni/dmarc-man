import os
from dotenv import load_dotenv
from pathlib import Path

env_path = Path('.') / '.env'
load_dotenv(dotenv_path=env_path)

EMAIL = os.environ['USER_NAME']
PASSWORD = os.environ['PASSWORD']
SERVER = os.environ['SERVER']
DMARC_EMAIL = os.environ['DMARC_EMAIL']
DMARC_EMAIL = DMARC_EMAIL.split(',')
SEND_SERVER = os.environ['SEND_SERVER']
WHITELISTED_EMAILS = os.environ['WHITELISTED_EMAILS']
WHITELISTED_EMAILS = WHITELISTED_EMAILS.split(',')
LAST_CHECK = None
DATE_FORMAT = "%d-%b-%Y"