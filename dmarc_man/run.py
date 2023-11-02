from datetime import datetime
import logging
from dmarc_man.config import *

from dmarc_man.email_utils import login_mail, fetch_emails, send_report
from dmarc_man.report_parser import parse_dmarc_report, generate_report_html

from dmarc_man.logger_config import logger


def get_last_check():
    """Reads the last check date from the file."""
    filename = "./dmarc_man/last_check"
    try:
        with open(filename, "r") as file:
            last_check_str = file.read().strip()
        datetime.strptime(last_check_str, DATE_FORMAT)
        return last_check_str
    except FileNotFoundError:
        logger.info(f"The file {filename} was not found.")
        return None
    except ValueError:
        logger.info(f"Invalid date format in {filename}. Expected dd-mmm-yyyy.")
        return None


def set_last_check():
    """Writes the current date to the file in dd-mmm-yyyy format."""
    filename = "./dmarc_man/last_check"
    current_date_str = datetime.now().strftime(DATE_FORMAT)
    with open(filename, "w") as file:
        file.write(current_date_str)


def fetch_dmarc_results(email_address):
    domain = (email_address.split("@"))[1]
    mail = login_mail(SERVER, EMAIL, PASSWORD, domain)
    messages = fetch_emails(mail, email_address, LAST_CHECK, domain)

    if len(messages) > 0:
        reports = [parse_dmarc_report(message, domain) for message in messages]
        html_content = generate_report_html(reports, domain)
        send_report(
            send_server=SEND_SERVER,
            username=EMAIL,
            password=PASSWORD,
            receiver_address=EMAIL,
            subject=f"{domain} DMARC Report",
            html_content=html_content,
            domain=domain,
            sender_address=email_address,
        )
    else:
        logger.info(f"[{domain}] No emails to analyse")


if __name__ == "__main__":
    LAST_CHECK = get_last_check()

    for email_addr in DMARC_EMAIL:
        fetch_dmarc_results(email_addr)

    set_last_check()
