import os
import email
import imaplib
from pathlib import Path
from dotenv import load_dotenv
from io import BytesIO
from zipfile import ZipFile
from xml.dom import minidom
import xmltodict, json
import datetime
from jinja2 import Environment, FileSystemLoader, select_autoescape
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.utils import formataddr, make_msgid
import xml.etree.ElementTree as ET

html_env = Environment(
    loader=FileSystemLoader(''),
    autoescape=select_autoescape(['html', 'xml'])
)

main_template = html_env.get_template('main.html')
report_template = html_env.get_template('report_child.html')
record_template = html_env.get_template('report_debug.html')

env_path = Path('.') / '.env'
load_dotenv(dotenv_path=env_path)

EMAIL = token=os.environ['USER_NAME']
PASSWORD = token=os.environ['PASSWORD']
SERVER = token=os.environ['SERVER']
DMARC_EMAIL = token=os.environ['DMARC_EMAIL']
DMARC_EMAIL = DMARC_EMAIL.split(',')
SEND_SERVER = token=os.environ['SEND_SERVER']
WHITELISTED_EMAILS = token=os.environ['WHITELISTED_EMAILS']
WHITELISTED_EMAILS = WHITELISTED_EMAILS.split(',')


def generate_report(email_address):
    domain = (email_address.split("@"))[1]

    mail = imaplib.IMAP4_SSL(SERVER)
    mail.login(EMAIL, PASSWORD)
    mail.select('inbox')

    # status, data = mail.search(None, '(TO "' + email_address + '" UNSEEN)')
    status, data = mail.search(None, '(TO "' + email_address + '")')

    # the list returned is a list of bytes separated
    # by white spaces on this format: [b'1 2 3', b'4 5 6']
    # so, to separate it first we create an empty list
    mail_ids = []
    # then we go through the list splitting its blocks
    # of bytes and appending to the mail_ids list
    for block in data:
        # the split function called without parameter
        # transforms the text or bytes into a list using
        # as separator the white spaces:
        # b'1 2 3'.split() => [b'1', b'2', b'3']
        mail_ids += block.split()

    main_verdict = 'pass'
    record_html = ''
    report = ''
    # now for every id we'll fetch the email
    # to extract its content
    for i in mail_ids:
        # the fetch function fetch the email given its id
        # and format that you want the message to be
        status, data = mail.fetch(i, '(RFC822)')

        # the content data at the '(RFC822)' format comes on
        # a list with a tuple with header, content, and the closing
        # byte b')'
        for response_part in data:
            # so if its a tuple...
            if isinstance(response_part, tuple):
                # we go for the content at its second element
                # skipping the header at the first and the closing
                # at the third
                message = email.message_from_bytes(response_part[1])

                # with the content we can extract the info about
                # who sent the message and its subject
                mail_from = message['from']
                mail_subject = message['subject']

                # stop if the mail is not from a whitelisted email address
                if mail_from not in WHITELISTED_EMAILS:
                    mail.store(i, '-FLAGS', '\Seen')
                    print("Ignoring email not whitelisted")
                    break

                # grab the list of emails previously checked by the program
                f = open("opened_emails", "r")
                opened_emails = list(filter(None, (f.read()).split(",")))
                f.close()

                # stop if the email has already been checked by the program
                if message["message-id"] in opened_emails:
                    print("Email already checked")
                    break

                opened_emails.append(message["message-id"])
                
                f = open("opened_emails", "w")
                f.write(','.join(opened_emails))
                f.close()

                for part in message.walk():
                    record_html = ''
                    if part.get_content_maintype() == 'multipart' and part.get('Content-Disposition') is None:
                        continue
                    file = part.get_payload(decode=True)

                    decompressed_data = ZipFile(BytesIO(file))

                    for zip_file in decompressed_data.namelist():
                        o = xmltodict.parse(decompressed_data.open(zip_file))

                        submittor_name = o["feedback"]["report_metadata"]["org_name"]
                        submittor_email = o["feedback"]["report_metadata"]["email"]
                        report_id = o["feedback"]["report_metadata"]["report_id"]
                        start_date_time = datetime.datetime.fromtimestamp(int(o["feedback"]["report_metadata"]["date_range"]["begin"]))  
                        end_date_time = datetime.datetime.fromtimestamp(int(o["feedback"]["report_metadata"]["date_range"]["end"]))  

                        for record in o["feedback"]["record"]:
                            if (record == "row" and type(record) == str) or type(record) == dict:
                                if type(record) == str:
                                    record_obj = o["feedback"]["record"][record]
                                elif type(record) == dict:
                                    record_obj = record["row"]
                            
                                if (record_obj["policy_evaluated"]["disposition"] == 'none'):
                                    msg_disposition = 'none'
                                elif (record_obj["policy_evaluated"]["disposition"] == 'quarantined'):
                                    msg_disposition = 'quarantined'
                                elif (record_obj["policy_evaluated"]["disposition"] == 'reject'):
                                    msg_disposition = 'reject'
                                else:
                                    msg_disposition = '???'

                                if (record_obj["policy_evaluated"]["dkim"] == 'pass'):
                                    msg_dkim = 'pass'
                                elif (record_obj["policy_evaluated"]["dkim"] == 'fail'):
                                    msg_dkim = 'fail'
                                else:
                                    msg_dkim = '???'

                                if (record_obj["policy_evaluated"]["spf"] == 'pass'):
                                    msg_spf = 'pass'
                                elif (record_obj["policy_evaluated"]["spf"] == 'fail'):
                                    msg_spf = 'fail'
                                else:
                                    msg_spf = '???'

                                if (msg_disposition != "none" or msg_dkim != "pass" or msg_spf != "pass"):
                                    verdict = "fail"
                                    main_verdict = 'attention'
                                else:
                                    verdict = "pass"

                                ip_address = (record_obj["source_ip"])
                                if (not all(ch in ".0123456789" for ch in ip_address)):
                                    ip_address = "???"

                                try:
                                    count = int(record_obj["count"])
                                except:
                                    count = "???"

                                record_html += (record_template.render(ip_address=ip_address, count=count, msg_disposition=msg_disposition, msg_spf=msg_spf, msg_dkim=msg_dkim, main_verdict=verdict))

                    if report != "":
                        report += '<hr>'
                    report += (report_template.render(date_start=start_date_time, date_end=end_date_time, report_id=report_id, submittor_name=submittor_name, submittor_email=submittor_email, report_debug=record_html))


                    
    if record_html:
        if main_verdict == 'attention':
            main_verdict = 'This report requires your attention.'
        elif main_verdict == 'pass':
            main_verdict = 'This report is OK.'
        else: 
            main_verdict = '???'

        main_ = main_template.render(verdict_summary=main_verdict, report=report, domain=domain)

        #The mail addresses and password
        sender_address = email_address
        receiver_address = EMAIL
        #Setup the MIME
        message = MIMEMultipart()
        message['From'] = formataddr(('DMARC Reports', sender_address))
        message['To'] = receiver_address
        message['Subject'] = domain + ' DMARC Report'   #The subject line
        message['Message-ID'] = make_msgid("_dmarc-man_report", domain)
        #The body and the attachments for the mail
        message.attach(MIMEText(main_, 'html'))
        #Create SMTP session for sending the mail
        session = smtplib.SMTP(SEND_SERVER, 587) #use gmail with port
        session.starttls() #enable security
        session.login(EMAIL, PASSWORD) #login with mail_id and password
        text = message.as_string()
        session.sendmail(sender_address, receiver_address, text)
        session.quit()
        print('Mail Sent')



for email_addr in DMARC_EMAIL:
    generate_report(email_addr)