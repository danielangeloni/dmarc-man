import imaplib
import email
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.utils import formataddr, make_msgid
from dmarc_man.logger_config import logger
from dmarc_man.config import WHITELISTED_EMAILS


def login_mail(server, email, password, domain):
    logger.info(f"[{domain}] Logging in")

    mail = imaplib.IMAP4_SSL(server)
    mail.login(email, password)
    mail.select("inbox")
    return mail


def fetch_emails(mail, email_address, last_check, domain):
    logger.info(f"[{domain}] Fetching all emails")
    search_query = f'(TO "{email_address}" SINCE "{last_check}")'
    status, data = mail.search(None, search_query)
    mail_ids = [item for sublist in data for item in sublist.split()]
    messages = []
    for email_id in mail_ids:
        status, data = mail.fetch(email_id, "(RFC822)")
        for response_part in data:
            if isinstance(response_part, tuple):
                message = email.message_from_bytes(response_part[1])
                mail_from = message["from"]

                if mail_from not in WHITELISTED_EMAILS:
                    # TO-DO: waht does this do
                    # mail.store(i, '-FLAGS', '\Seen')
                    logger.info(
                        f"[{domain}] Ignoring email from {mail_from} as it is not whitelisted"
                    )
                    continue

                messages.append(message)
    return messages


def send_report(
    send_server,
    username,
    password,
    receiver_address,
    subject,
    html_content,
    domain,
    sender_address,
):
    session = smtplib.SMTP_SSL(send_server, 465)
    session.login(username, password)
    message = MIMEMultipart()
    message["From"] = formataddr(("DMARC Reports", sender_address))
    message["To"] = receiver_address
    message["Subject"] = subject
    message["Message-ID"] = make_msgid("_dmarc-man_report", domain)
    message.attach(MIMEText(html_content, "html"))
    session.sendmail(sender_address, receiver_address, message.as_string())
    session.quit()
    logger.info(f"[{domain}] Mail sent")
