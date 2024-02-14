import requests
import os
import sqlite3
from Modules.Alerts.Discord_webhook import send_cve_webhook

DB_path = 'Modules/Database/CVE/CVE_DATA.db'


def create_cves_table():
    if not os.path.exists(f"Modules/Database/CVE/CVE_DATA.db"):
        os.makedirs("Modules/Database/CVE")
        conn = sqlite3.connect('Modules/Database/CVE/CVE_DATA.db')
        cursor = conn.cursor()

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS cves (
                id TEXT PRIMARY KEY,
                assigner TEXT,
                description TEXT,
                cvss_score TEXT,
                published TEXT,
                modified TEXT,
                last_modified TEXT,
                references_ TEXT
            )
        ''')

        conn.commit()
        conn.close()


def insert_cves_db(cve_data):
    conn = sqlite3.connect(DB_path)
    cursor = conn.cursor()

    cursor.execute('''
        INSERT INTO cves (id, assigner, description, cvss_score, published, modified, last_modified, references_)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    ''', (
        cve_data["Id"],
        cve_data["Assigner"],
        cve_data["Description"],
        cve_data["CVSS_Score"],
        cve_data["Published"],
        cve_data["Modified"],
        cve_data["Last_Modified"],
        cve_data["References"]
    ))

    conn.commit()
    conn.close()


def check_cves_db(cve_id, last_modified, cve_data):
    conn = sqlite3.connect(DB_path)
    cursor = conn.cursor()

    cursor.execute('''SELECT last_modified FROM cves WHERE id = ?''', (cve_id,))

    result = cursor.fetchone()

    if result:
        if result[0] != last_modified:
            cursor.execute('''
                UPDATE cves 
                SET assigner = ?,
                    description = ?,
                    cvss_score = ?,
                    published = ?,
                    modified = ?,
                    last_modified = ?,
                    references_ = ?
                WHERE id = ?
            ''', (
                cve_data["Assigner"],
                cve_data["Description"],
                cve_data["CVSS_Score"],
                cve_data["Published"],
                cve_data["Modified"],
                cve_data["Last_Modified"],
                cve_data["References"],
                cve_id
            ))
            conn.commit()
            conn.close()

            return 'update'.lstrip()

        else:
            return False

    else:
        return True


def get_latest_cves(num_cves):
    url = f"https://cve.circl.lu/api/last/{num_cves}"
    response = requests.get(url)
    if response.status_code == 200:
        cves = response.json()
        return cves
    else:
        print("Error retrieving CVE.")
        print(response.text)
        return None


def CVE_Monitor_SCAN(num_cves=1):
    create_cves_table()
    cves = get_latest_cves(num_cves)
    if cves:
        for cve in cves:

            cve_data = {
                "Id": f"{cve['id']}",
                "Assigner": f"{cve['assigner']}",
                "Description": f"{cve['summary']}",
                "CVSS_Score": f"{cve['cvss']}",
                "References": f"{cve['references']}",
                "Published": f"{cve['Published']}",
                "Modified": f"{cve['Modified']}",
                "Last_Modified": f"{cve['last-modified']}"
            }

            result = check_cves_db(cve['id'], cve['last-modified'], cve_data)

            if result == 'update':
                print(f"Update de la cve : {cve['id']}")
                send_cve_webhook(cve_data)
            elif result:
                insert_cves_db(cve_data)
                send_cve_webhook(cve_data)
