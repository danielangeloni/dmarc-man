import gzip
from io import BytesIO
from zipfile import ZipFile
import xmltodict
from datetime import datetime
import ipaddress
import xml.etree.ElementTree as ET
from jinja2 import Environment, FileSystemLoader, select_autoescape
from dmarc_man.logger_config import logger

html_env = Environment(
    loader=FileSystemLoader(""), autoescape=select_autoescape(["html", "xml"])
)

main_template = html_env.get_template("./dmarc_man/templates/main.html")
report_template = html_env.get_template("./dmarc_man/templates/report_child.html")
record_template = html_env.get_template("./dmarc_man/templates/report_debug.html")


def decompress_data(file_data, max_decompressed_size=5242880):
    if file_data.startswith(b"\x1f\x8b"):  # GZ header
        decompressed = gzip.decompress(file_data)
        if len(decompressed) > max_decompressed_size:
            raise ValueError("Decompressed data too large!")
        return [decompressed.decode()]
    elif file_data.startswith(b"PK\x03\x04"):  # ZIP header
        decompressed_files = []
        with ZipFile(BytesIO(file_data)) as zipf:
            for name in zipf.namelist():
                data = zipf.read(name)
                if len(data) > max_decompressed_size:
                    raise ValueError("Decompressed data too large!")
                decompressed_files.append(data.decode())
        return decompressed_files
    else:
        raise ValueError("Unsupported compression format")


def check_ip(ip_str):
    try:
        ipaddress.ip_address(ip_str)
        return True
    except ValueError:
        return False


def parse_dmarc_report(message, domain):
    logger.info(f"[{domain}] Analysing email")
    results = []

    for part in message.walk():
        if part.get_content_maintype() != "application":
            continue

        file = part.get_payload(decode=True)
        decompressed_files = decompress_data(file)

        for decompressed_data in decompressed_files:
            o = xmltodict.parse(decompressed_data)

            result = {
                "submittor_name": None,
                "submittor_email": None,
                "report_id": None,
                "start_datetime": None,
                "end_datetime": None,
                "main_verdict": "pass",
                "records": [],
            }

            result["submittor_name"] = o["feedback"]["report_metadata"]["org_name"]
            result["submittor_email"] = o["feedback"]["report_metadata"]["email"]
            result["report_id"] = o["feedback"]["report_metadata"]["report_id"]
            result["start_datetime"] = datetime.fromtimestamp(
                int(o["feedback"]["report_metadata"]["date_range"]["begin"])
            ).strftime("%Y-%m-%d %H:%M:%S")
            result["end_datetime"] = datetime.fromtimestamp(
                int(o["feedback"]["report_metadata"]["date_range"]["end"])
            ).strftime("%Y-%m-%d %H:%M:%S")

            if isinstance(o["feedback"]["record"], dict):
                o["feedback"]["record"] = [o["feedback"]["record"]]

            for record in o["feedback"]["record"]:
                record_dict = {
                    "disposition": None,
                    "dkim": None,
                    "spf": None,
                    "verdict": "pass",
                    "ip_address": None,
                    "count": None,
                    "envelope_to": None,
                    "envelope_from": None,
                    "header_from": None,
                }

                if isinstance(record, dict):
                    record_obj = record["row"]
                elif record == "row":
                    record_obj = o["feedback"]["record"][record]
                else:
                    continue

                allowed_disposition_values = ["none", "quarantined", "reject"]
                disposition = record_obj["policy_evaluated"]["disposition"]
                if disposition in allowed_disposition_values:
                    record_dict["disposition"] = disposition

                allowed_dkim_values = ["pass", "fail"]
                dkim = record_obj["policy_evaluated"]["dkim"]
                if dkim in allowed_dkim_values:
                    record_dict["dkim"] = dkim

                allowed_spf_values = ["pass", "fail"]
                spf = record_obj["policy_evaluated"]["spf"]
                if spf in allowed_spf_values:
                    record_dict["spf"] = spf

                if any([disposition != "none", dkim != "pass", spf != "pass"]):
                    record_dict["verdict"] = "fail"
                    result["main_verdict"] = "attention"

                ip_address = record_obj["source_ip"]
                record_dict["ip_address"] = ip_address

                record_dict["ip_address"] = (
                    record_dict["ip_address"]
                    if check_ip(record_dict["ip_address"])
                    else "???"
                )

                record_dict["envelope_to"] = record["identifiers"].get(
                    "envelope_to", None
                )
                record_dict["envelope_from"] = record["identifiers"].get(
                    "envelope_from", None
                )
                record_dict["header_from"] = record["identifiers"].get(
                    "header_from", None
                )

                try:
                    record_dict["count"] = int(record_obj["count"])
                except:
                    record_dict["count"] = "???"

                result["records"].append(record_dict)

        results.append(result)
        return result


def generate_report_html(reports, domain):
    html = []

    main_verdict = "pass"

    for report in reports:
        if report["main_verdict"] != "pass":
            main_verdict = report["main_verdict"]

        records = report["records"]
        records_html = []

        for record in records:
            records_html.append(
                record_template.render(
                    ip_address=record["ip_address"],
                    count=record["count"],
                    msg_disposition=record["disposition"],
                    msg_spf=record["spf"],
                    msg_dkim=record["dkim"],
                    main_verdict=record["verdict"],
                    envelope_to=record["envelope_to"],
                    envelope_from=record["envelope_from"],
                    header_from=record["header_from"],
                )
            )

        records_html = "".join(records_html)

        html.append(
            report_template.render(
                date_start=report["start_datetime"],
                date_end=report["end_datetime"],
                report_id=report["report_id"],
                submittor_name=report["submittor_name"],
                submittor_email=report["submittor_email"],
                report_debug=records_html,
            )
        )

        # <hr>
    html = "<hr>".join(html)

    verdict_map = {
        "attention": "This report requires your attention.",
        "pass": "This report is OK.",
    }

    main_verdict = verdict_map.get(main_verdict, "???")

    return main_template.render(
        verdict_summary=main_verdict, report=html, domain=domain
    )
