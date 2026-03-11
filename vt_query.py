"""
Модуль работы с VirusTotal API.

Используется для проверки IP-адресов,
обнаруженных в логах Suricata.

API ключ читается из переменной окружения:
VT_API_KEY
"""

import os
import requests

VT_API_KEY = os.getenv("VT_API_KEY")
VT_BASE = "https://www.virustotal.com/api/v3"

def vt_enabled():
    """
    Проверяет установлен ли API ключ VirusTotal.
    """
    return VT_API_KEY is not None and VT_API_KEY != ""

def query_ip(ip):
    """
    Отправляет запрос к VirusTotal для проверки IP.
    """
    if not vt_enabled():
        return None
    headers = {"x-apikey": VT_API_KEY}
    url = f"{VT_BASE}/ip_addresses/{ip}"
    try:
        r = requests.get(url, headers=headers, timeout=15)
        if r.status_code != 200:
            return None
        data = r.json()
        stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        malicious = stats.get("malicious", 0)

        return {
            "ip": ip,
            "malicious_count": malicious
        }

    except Exception:

        return None