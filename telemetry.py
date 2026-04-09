import psutil
import time
import json
from datetime import datetime

def get_top_processes(limit=5):
    processes = []
    for p in psutil.process_iter(['pid', 'name', 'cpu_percent']):
        try:
            processes.append(p.info)
        except:
            continue

    processes = sorted(processes, key=lambda x: x['cpu_percent'], reverse=True)
    return processes[:limit]

def get_metrics():
    return {
        "timestamp": str(datetime.now()),
        "cpu_percent": psutil.cpu_percent(interval=None),
        "memory_percent": psutil.virtual_memory().percent,
        "top_processes": get_top_processes()
    }

if __name__ == "__main__":
    while True:
        metrics = get_metrics()
        print(json.dumps(metrics, indent=2))
        time.sleep(2)