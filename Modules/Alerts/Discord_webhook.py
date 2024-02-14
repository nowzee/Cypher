import requests
import configparser


def read_config(file_path):
    config = configparser.ConfigParser()

    config.read(file_path)

    try:
        Webhook = config['Alert_CVE_Monitor'].get('Discord_webhook')
        return Webhook
    except Exception as e:
        print(f"Error : please check config file : Modules/config.ini : {e}")
        exit()


config_file = 'Modules/config.ini'
url = read_config(config_file)


def send_cve_webhook(cve_data):
    cvename = cve_data["Id"]
    description = cve_data["Description"]
    cvss = cve_data["CVSS_Score"]
    Published = cve_data["Published"]
    last_modified = cve_data["Last_Modified"]

    data = {
        "avatar_url": "",  # enter your url ;)
        "username": "Cypher - CVE",
        "embeds": [{
            "title": f"{cvename}",
            "fields": [
                {"name": "", "value": f"{description}", "inline": False},
                {"name": "CVSS", "value": f"{cvss}", "inline": True},
                {"name": "Published", "value": f"{Published}", "inline": True},
                {"name": "Last Modified", "value": f"{last_modified}", "inline": True},
                {"name": "More details", "value": f"https://cve.circl.lu/cve/{cvename}", "inline": False}
            ],

            "footer": {
                "text": "A new cve has appeared"
            },
            "author": {
                "name": "CVE monitor"
            },
            "color": 0x09090D
        }]
    }

    requests.post(url, json=data)
