
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

    # -----------------------------
    # ЭТАП 2 — АНАЛИЗ
    # -----------------------------

    # подсчёт количества событий по IP
    ip_counts = df["src_ip"].value_counts().reset_index()
    ip_counts.columns = ["ip", "count"]

    # выбираем самые активные IP
    top_ips = ip_counts.head(TOP_IP_CHECK).copy()

    vt_results = []

    # проверка VirusTotal
    if not vt_enabled():
        print("VirusTotal API key not found. Skipping VT checks.")

    else:
        print("Checking IPs via VirusTotal...")

        for ip in top_ips["ip"]:
            result = query_ip(ip)

            if result:
                vt_results.append(result)

    vt_df = pd.DataFrame(vt_results)

    # объединение результатов
    if not vt_df.empty:
        report_df = top_ips.merge(vt_df, on="ip", how="left")
    else:
        report_df = top_ips
        report_df["malicious_count"] = None

    # определяем подозрительные IP
    def suspicious(row):

        if row["count"] >= SUSPICIOUS_EVENT_COUNT:
            return True

        if row.get("malicious_count") and row["malicious_count"] > 0:
            return True

        return False

    report_df["suspicious"] = report_df.apply(suspicious, axis=1)

    suspicious_ips = report_df[report_df["suspicious"] == True]["ip"].tolist()

    # -----------------------------
    # ЭТАП 3 — РЕАКЦИЯ
    # -----------------------------

    respond_to_threats(suspicious_ips)

    # -----------------------------
    # ЭТАП 4 — ОТЧЁТ
    # -----------------------------

    # сохраняем отчёты
    csv_path = os.path.join(OUTPUT_DIR, "report.csv")
    json_path = os.path.join(OUTPUT_DIR, "report.json")

    report_df.to_csv(csv_path, index=False)
    report_df.to_json(json_path, orient="records", indent=2)

    print("Reports saved.")

    # строим график
    top5 = report_df.head(5)

    plt.figure(figsize=(8, 5))

    sns.barplot(x="ip", y="count", data=top5)

    plt.title("Top 5 source IPs")

    plt.tight_layout()

    chart_path = os.path.join(OUTPUT_DIR, "top_ips.png")

    plt.savefig(chart_path)

    print("Chart saved.")


if __name__ == "__main__":

    analyze()