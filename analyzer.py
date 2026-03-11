
import os
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns

from parse_suricata import load_suricata_eve
from vt_query import query_ip, vt_enabled
from response import respond_to_threats

# -----------------------------
# Настройки программы
# -----------------------------
# путь к Suricata логам
SURICATA_LOG_FILE = "logs/eve.json"
# папка для результатов
OUTPUT_DIR = "output"
# сколько событий должно быть чтобы IP считался подозрительным
SUSPICIOUS_EVENT_COUNT = 10
# сколько IP проверять через VirusTotal
TOP_IP_CHECK = 10

def analyze():
    """
    Основная функция анализа угроз.
    """
    # создаём папку output если её нет
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    print("Loading Suricata logs...")
    # -----------------------------
    # ЭТАП 1 — СБОР ДАННЫХ
    # -----------------------------
    df = load_suricata_eve(SURICATA_LOG_FILE)
    if df.empty:
        print("Log file is empty")
        return
    print("Events loaded:", len(df))



if __name__ == "__main__":

    analyze()