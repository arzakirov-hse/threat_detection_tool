"""
Модуль загрузки логов Suricata.

Поддерживает два формата:

1. Suricata EVE JSON lines
   (каждое событие — отдельная строка)

2. JSON массив
   [
     {...},
     {...}
   ]

Функция возвращает pandas DataFrame для дальнейшего анализа.
"""

import json
import pandas as pd

def load_suricata_eve(path):
    """
    Загружает Suricata лог и преобразует его в DataFrame.
    """
    with open(path, "r", encoding="utf-8") as f:
        content = f.read().strip()
    rows = []
    # если файл начинается с [, значит это JSON массив
    if content.startswith("["):
        data = json.loads(content)
        for event in data:
            row = {
                "timestamp": event.get("timestamp"),
                "event_type": event.get("event_type"),
                "src_ip": event.get("src_ip"),
                "dest_ip": event.get("dest_ip"),
                "proto": event.get("proto")
            }
            alert = event.get("alert")
            if alert:
                row["signature"] = alert.get("signature")
                row["severity"] = alert.get("severity")
            else:
                row["signature"] = None
                row["severity"] = None
            rows.append(row)

    else:
        # формат JSON lines
        for line in content.splitlines():
            if not line.strip():
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            row = {
                "timestamp": event.get("timestamp"),
                "event_type": event.get("event_type"),
                "src_ip": event.get("src_ip"),
                "dest_ip": event.get("dest_ip"),
                "proto": event.get("proto")
            }
            alert = event.get("alert")
            if alert:
                row["signature"] = alert.get("signature")
                row["severity"] = alert.get("severity")
            else:
                row["signature"] = None
                row["severity"] = None
            rows.append(row)
    df = pd.DataFrame(rows)
    if not df.empty:
        df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
    return df