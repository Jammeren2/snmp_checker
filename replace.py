
# import sqlite3
# import re

# # Подключаемся к базе данных SQLite
# conn = sqlite3.connect('C:\\Users\\my\\Desktop\\py\\practic\\snmp_check\\links\\network_links.db')
# cursor = conn.cursor()

# # Функция для замены IP-адресов
# def replace_ip(ip_address):
#     # Ищем паттерн 10.x.5.x и заменяем его на 192.x.0.x
#     return re.sub(r'10\.(\d+)\.5\.(\d+)', r'192.\1.0.\2', ip_address)

# # Выбираем все строки из таблицы networks
# cursor.execute("SELECT id, device_ip FROM devices")
# rows = cursor.fetchall()

# # Обновляем IP-адреса в базе данных
# for row in rows:
#     new_ip = replace_ip(row[1])
#     cursor.execute("UPDATE devices SET device_ip = ? WHERE id = ?", (new_ip, row[0]))

# # Сохраняем изменения и закрываем соединение
# conn.commit()
# conn.close()


import sqlite3

# Подключаемся к базе данных SQLite
conn = sqlite3.connect('C:\\Users\\my\\Desktop\\py\\practic\\snmp_check\\links\\network_links.db')
cursor = conn.cursor()

# Функция для извлечения последних цифр из IP-адреса
def extract_last_segment(ip_address):
    # Разбиваем IP-адрес по точкам и берем последний сегмент
    return ip_address.split('.')[-1]

# Выбираем все строки из таблицы devices
cursor.execute("SELECT id, device_ip FROM devices")
rows = cursor.fetchall()

# Обновляем device_name для каждой записи
for row in rows:
    last_segment = extract_last_segment(row[1])
    new_device_name = f"switch {last_segment}"
    cursor.execute("UPDATE devices SET device_name = ? WHERE id = ?", (new_device_name, row[0]))

# Сохраняем изменения и закрываем соединение
conn.commit()
conn.close()
