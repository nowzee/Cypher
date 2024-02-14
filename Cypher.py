import threading
import time
from Modules.Search_module.CVE_Monitor import CVE_Monitor_SCAN


def run_CVE_Monitor_SCAN():
    print("Cypher has ready", end='')
    while True:
        CVE_Monitor_SCAN(num_cves=100)
        time.sleep(3600)  # 1 hour


thread = threading.Thread(target=run_CVE_Monitor_SCAN)

thread.start()
