"""
Модуль реагирования на угрозы.
Сейчас просто заглушка — вывод сообщения о блокировке IP.
"""

def block_ip(ip):
    """
    Имитация блокировки IP.
    """

    print(f"[RESPONSE] Blocking IP: {ip}")

def respond_to_threats(ip_list):
    """
    Обрабатывает список подозрительных IP.
    """
    if not ip_list:
        print("No threats detected.")
        return
    print("Threats detected. Starting response...")
    for ip in ip_list:
        block_ip(ip)