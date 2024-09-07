import re
import json
from mac_vendor_lookup import MacLookup
from pysnmp.hlapi import *
from concurrent.futures import ThreadPoolExecutor
from collections import defaultdict
import sys
import os
import sqlite3
from datetime import datetime
import subprocess
import ipaddress


cIDs = { # chassis ID subtypes
    1: "Chassis component",
    2: "Interface alias",
    3: "Port component",
    4: "MAC address",
    5: "Network address",
    6: "Interface name",
    7: "Locally assigned"
}

pIDs = { # port ID subtypes
    1: "Interface alias",
    2: "Port component",
    3: "MAC address",
    4: "Network address",
    5: "Interface name",
    6: "Agent circuit ID",
    7: "Locally assigned"
}

oids = {
    'lldpRemChassisIdSubtype': '1.0.8802.1.1.2.1.4.1.1.4',
    'lldpRemChassisId': '1.0.8802.1.1.2.1.4.1.1.5',
    'lldpRemPortIdSubtype': '1.0.8802.1.1.2.1.4.1.1.6',
    'lldpRemPortId': '1.0.8802.1.1.2.1.4.1.1.7',
    'lldpRemSysName': '1.0.8802.1.1.2.1.4.1.1.9',
    'lldpRemSysDesc': '1.0.8802.1.1.2.1.4.1.1.10',
}
oids2 = {
    'GetAllConnect': '1.3.6.1.2.1.4.22.1.1.12',
    'GetAllNamesRemoteSystem': '1.0.8802.1.1.2.1.4.1.1.9',
    'GetOnlyOneMac': '1.3.6.1.2.1.2.2.1.6.5121',
    'GetAllMac': '1.3.6.1.2.1.2.2.1.6',
    'SystemName': '1.3.6.1.2.1.1.5',
    'AbsoluteSystemName': '1.3.6.1.2.1.1.5.0',
}



def snmp_get_next(target, oid):
    iterator = nextCmd(
        SnmpEngine(),
        CommunityData('public'),
        UdpTransportTarget((target, 161)),
        ContextData(),
        ObjectType(ObjectIdentity(oid)),
        lexicographicMode=False
    )

    results = {}
    for (errorIndication, errorStatus, errorIndex, varBinds) in iterator:
        if errorIndication:
            print(errorIndication)
            break
        elif errorStatus:
            print('%s at %s' % (errorStatus.prettyPrint(), errorIndex and varBinds[int(errorIndex) - 1][0] or '?'))
            break
        else:
            for varBind in varBinds:
                results[str(varBind[0])] = str(varBind[1])
    return results

mac_re = re.compile(r'\w\w:\w\w:\w\w:\w\w:\w\w:\w\w')
nbsp = re.compile(r'&nbsp;')
mac = MacLookup()

def serialize_ports(data):
    if isinstance(data, dict):
        return {k: serialize_ports(v) for k, v in data.items()}
    elif isinstance(data, list):
        return [serialize_ports(v) for v in data]
    elif isinstance(data, (int, str)):
        return data
    elif hasattr(data, 'prettyPrint'):  # for pysnmp objects
        return data.prettyPrint()
    else:
        return str(data)

# Function to get information
def get_info(host):
    ports = {}

    def nextSNMP(oid):
        return nextCmd(SnmpEngine(),
                       CommunityData('public', mpModel=1),  # v2c
                       UdpTransportTarget((host, 161)),
                       ContextData(),
                       ObjectType(ObjectIdentity(oid)))

    for key in oids.keys():
        for errorIndication, errorStatus, errorIndex, varBinds in nextSNMP(oids[key]):
            if oids[key] not in str(varBinds[0][0]): break
            for varBind in varBinds:
                parts = str(varBind[0]).split('.')
                if len(parts) < 14:
                    continue
                port = parts[12]
                ent = parts[13]
                if port not in ports: ports[port] = {}
                if ent not in ports[port]: ports[port][ent] = {}
                ports[port][ent][key] = varBind[1]

    for port in ports:
        for ent in ports[port]:
            for key in ports[port][ent]:
                if key == 'lldpRemChassisIdSubtype' or key == 'lldpRemPortIdSubtype':
                    ports[port][ent][key] = int(ports[port][ent][key])
                elif key == 'lldpRemChassisId':
                    if ports[port][ent].get('lldpRemChassisIdSubtype') == 4:
                        if not mac_re.match(str(ports[port][ent][key])):
                            ports[port][ent][key] = ':'.join(['%.2x' % x for x in ports[port][ent][key].asNumbers()])
                        try:
                            ports[port][ent][key] += ' (' + mac.lookup(ports[port][ent][key]) + ')'
                        except:
                            ports[port][ent][key] += ' (not found)'
                    elif ports[port][ent].get('lldpRemChassisIdSubtype') == 5:
                        ports[port][ent][key] = '.'.join(['%.d' % x for x in ports[port][ent][key][1:].asNumbers()])
                elif key == 'lldpRemPortId':
                    if ports[port][ent].get('lldpRemPortIdSubtype') == 3:
                        ports[port][ent][key] = ':'.join(['%.2x' % x for x in ports[port][ent][key].asNumbers()])
                        try:
                            ports[port][ent][key] += ' (' + mac.lookup(ports[port][ent][key]) + ')'
                        except:
                            ports[port][ent][key] += ' (not found)'
                    elif ports[port][ent].get('lldpRemPortIdSubtype') == 4:
                        ports[port][ent][key] = '.'.join(['%.d' % x for x in ports[port][ent][key][1:].asNumbers()])
                elif key == 'lldpRemSysDesc':
                    ports[port][ent][key] = nbsp.sub(' ', str(ports[port][ent][key]))
    return ports


def get_sus_name(ip):
    system_name_result = snmp_get_next(ip, oids2['SystemName'])
    return system_name_result.get(oids2['AbsoluteSystemName'], '')


def get_sus_mac(ip):
    result = None  # Initialize result
    mac_result = snmp_get_next(ip, oids2['GetAllMac'])
    mac_value = mac_result.get(oids2['GetOnlyOneMac'], '')

    if mac_value:
        if not mac_re.match(mac_value):
            mac_bytes = [ord(x) for x in mac_value]
            result = ':'.join(['%.2x' % x for x in mac_bytes])
        else:
            result = mac_value
    else:
        if mac_result:
            last_key = max(mac_result.keys(), key=lambda x: int(x.split('.')[-1]))
            last_mac_value = mac_result[last_key]
            if not mac_re.match(last_mac_value):
                mac_bytes = [ord(x) for x in last_mac_value]
                result = ':'.join(['%.2x' % x for x in mac_bytes])
            else:
                result = last_mac_value
        else:
            print("No SNMP response received or empty result set")

    if result:
        return result
    else:
        return "00:00:00:00:00:00"


def transform_data(data):
    transformed = {"devices": []}
    for device in data:
        new_device = {
            "ip": device["ip"],
            "name": device["name"],
            "mac": device["mac"],
            "ports": []
        }
        for port, connections in device["ports"].items():
            for connection in connections.values():
                new_device["ports"].append({
                    "port": int(port),
                    "connections": [{
                        "remote_ip": "not found",
                        "remote_mac": connection.get("lldpRemChassisId", "unknown").split(" ")[0],
                        "remote_port": connection.get("lldpRemPortId", "unknown"),
                        "remote_name": connection.get("lldpRemSysName", "unknown"),
                        "remote_desc": connection.get("lldpRemSysDesc", "unknown")
                    }]
                })
        transformed["devices"].append(new_device)
    return transformed

def fetch_info(ip):
    remote_system_names = get_info(ip)
    print (ip)
    ports_serializable = serialize_ports(remote_system_names)
    return {"ip": ip, "name": get_sus_name(ip), "mac": get_sus_mac(ip), "ports": ports_serializable}



def merge_connections(connections):
    merged = {}
    for conn in connections:
        mac = conn["remote_mac"]
        if mac not in merged:
            merged[mac] = conn
        else:
            for key, value in conn.items():
                if key not in merged[mac]:
                    merged[mac][key] = value
                elif merged[mac][key] != value:
                    if isinstance(merged[mac][key], list):
                        if value not in merged[mac][key]:
                            merged[mac][key].append(value)
                    else:
                        merged[mac][key] = [merged[mac][key], value]
    return list(merged.values())

def process_ports(ports):
    port_dict = defaultdict(list)
    for port in ports:
        port_dict[port["port"]].extend(port["connections"])
    
    processed_ports = []
    for port, connections in port_dict.items():
        merged_connections = merge_connections(connections)
        processed_ports.append({
            "port": port,
            "connections": merged_connections
        })
    
    return processed_ports

def process_devices(devices):
    for device in devices:
        device["ports"] = process_ports(device["ports"])
    return devices

def update_mac_addresses(devices):
    name_to_mac = {}
    
    # Создаем словарь для поиска устройства по имени
    for device in devices:
        if device['name'] and device['mac'] != '00:00:00:00:00:00':
            name_to_mac[device['name']] = device['mac']
        for port in device.get('ports', []):
            for connection in port.get('connections', []):
                remote_name = connection['remote_name']
                remote_mac = connection['remote_mac']
                if isinstance(remote_name, list):
                    for name in remote_name:
                        if name and remote_mac != '00:00:00:00:00:00':
                            name_to_mac[name] = remote_mac
                else:
                    if remote_name and remote_mac != '00:00:00:00:00:00':
                        name_to_mac[remote_name] = remote_mac

    # Обновляем MAC-адреса устройств с нулевым MAC
    for device in devices:
        if device['mac'] == '00:00:00:00:00:00' and device['name'] in name_to_mac:
            device['mac'] = name_to_mac[device['name']]
        for port in device.get('ports', []):
            for connection in port.get('connections', []):
                remote_name = connection['remote_name']
                if isinstance(remote_name, list):
                    for name in remote_name:
                        if name in name_to_mac and connection['remote_mac'] == '00:00:00:00:00:00':
                            connection['remote_mac'] = name_to_mac[name]
                else:
                    if remote_name in name_to_mac and connection['remote_mac'] == '00:00:00:00:00:00':
                        connection['remote_mac'] = name_to_mac[remote_name]

    return devices
def combine_ports(port_connections):
    combined = defaultdict(lambda: {
        "remote_ip": "not found",
        "remote_mac": set(),
        "remote_port": set(),
        "remote_name": set(),
        "remote_desc": ""
    })

    for conn in port_connections:
        remote_names = conn['remote_name']
        remote_ports = conn['remote_port']

        # Convert single values to lists for uniform processing
        if not isinstance(remote_names, list):
            remote_names = [remote_names]
        if not isinstance(remote_ports, list):
            remote_ports = [remote_ports]

        for name in remote_names:
            combined[name]['remote_ip'] = conn['remote_ip']
            combined[name]['remote_name'].update(remote_names)
            combined[name]['remote_desc'] = conn['remote_desc']
            
            if isinstance(conn['remote_mac'], list):
                combined[name]['remote_mac'].update(conn['remote_mac'])
            else:
                combined[name]['remote_mac'].add(conn['remote_mac'])
            
            combined[name]['remote_port'].update(remote_ports)

    for k, v in combined.items():
        v['remote_mac'] = list(v['remote_mac'])
        v['remote_port'] = list(v['remote_port'])
        v['remote_name'] = list(v['remote_name'])
        if len(v['remote_mac']) == 1:
            v['remote_mac'] = v['remote_mac'][0]
        if len(v['remote_port']) == 1:
            v['remote_port'] = v['remote_port'][0]
        if len(v['remote_name']) == 1:
            v['remote_name'] = v['remote_name'][0]

    return list(combined.values())

def process_device_data(device_data):
    for device in device_data:
        for port in device['ports']:
            port['connections'] = combine_ports(port['connections'])
    return device_data
def is_valid_mac(mac):
    if isinstance(mac, list):
        return all(re.match(r'^([0-9a-f]{2}:){5}([0-9a-f]{2})$', m.lower()) for m in mac)
    return re.match(r'^([0-9a-f]{2}:){5}([0-9a-f]{2})$', mac.lower()) is not None

def get_all_macs(devices):
    macs = []
    for device in devices:
        macs.append(device['mac'].lower())
    return macs

def clean_connections(data):
    valid_macs = set(get_all_macs(data))
    for device in data:
        cleaned_ports = []
        for port in device.get('ports', []):
            valid_connections = []
            for conn in port['connections']:
                remote_macs = conn['remote_mac'] if isinstance(conn['remote_mac'], list) else [conn['remote_mac']]
                normalized_remote_macs = [mac.lower() for mac in remote_macs]
                if any(is_valid_mac(mac) and mac in valid_macs for mac in normalized_remote_macs):
                    conn['remote_mac'] = normalized_remote_macs if isinstance(conn['remote_mac'], list) else normalized_remote_macs[0]
                    valid_connections.append(conn)
            if valid_connections:
                port['connections'] = valid_connections
                cleaned_ports.append(port)
        device['ports'] = cleaned_ports
        device['mac'] = device['mac'].lower()
    return data
def clean_remote_mac(entries):
    for entry in entries:
        for port in entry.get("ports", []):
            for connection in port.get("connections", []):
                remote_mac = connection.get("remote_mac")
                if isinstance(remote_mac, list) and len(remote_mac) > 0:
                    # Keep only the first MAC address in the list
                    connection["remote_mac"] = remote_mac[0]
    return entries
def replace_mac_addresses(data, old_mac, new_mac):
    if isinstance(data, dict):
        for key, value in data.items():
            if value == old_mac:
                data[key] = new_mac
            elif isinstance(value, (dict, list)):
                replace_mac_addresses(value, old_mac, new_mac)
    elif isinstance(data, list):
        for item in data:
            replace_mac_addresses(item, old_mac, new_mac)
    return data


# Функция для удаления ненужных полей из данных
def remove_fields(data, fields_to_remove):
    for item in data:
        for port in item.get('ports', []):
            for connection in port.get('connections', []):
                for field in fields_to_remove:
                    if field in connection:
                        del connection[field]
    return data

def get_ip_adrss(host):
    # host = sys.argv[1]
    oid = '1.3.6.1.2.1.4.22.1.2'   # ipNetToMediaPhysAddress :: 1.3.6.1.2.1.4.22.1.2.x.a.b.c.d :: x - interface index, a.b.c.d - ip address
    ip_adrss = []
    def nextSNMP(oid):
        return nextCmd(SnmpEngine(),
                       CommunityData('public', mpModel = 1),  # v2c
                       UdpTransportTarget((host, 161)),
                       ContextData(),
                       ObjectType(ObjectIdentity(oid)))

    net = ipaddress.ip_interface(host + '/24').network    # технологическая подсеть /24 (256 адресов), использовать ip роутера из одной подсети со остальными устройствами
    print('Network:', net)

    param = '-n' if os.sys.platform.lower() == 'win32' else '-c'   # если винда, ping -n 1, иначе -с 1, посылать по одному пакету
    for ip in net.hosts():
        subprocess.Popen(['ping', param, '1', str(ip)], stdout = subprocess.DEVNULL, stderr = subprocess.DEVNULL)    # посалаем пинги на всю подсеть не дожидаясь ответа

    for errorIndication, errorStatus, errorIndex, varBinds in nextSNMP(oid):    # читаем ARP-таблицу (прям всю, может быть довольно долго)
        if oid not in str(varBinds[0][0]): break
        for varBind in varBinds:
            ip = ipaddress.ip_address(re.findall(f'^{oid}\.\d+\.([0-9.]+)$', str(varBind[0]))[0])   # ip - последние 4 числа в oid'е
            if ip in net:
                mac = ':'.join(['%.2x' % x for x in varBind[1].asNumbers()])    # mac - значение по oid'у, формат OctetString
                if(mac):
                    # print(mac, ip)
                    ip_adrss.append(str(ip))  
    return ip_adrss

def update_remote_macs(data):
    # Создаем словарь для быстрого поиска mac по имени устройства
    name_to_mac = {item['name']: item['mac'] for item in data}

    # Обходим все устройства и их порты, чтобы обновить remote_mac
    for device in data:
        for port in device.get('ports', []):
            for connection in port.get('connections', []):
                remote_name = connection['remote_name']
                # Проверяем, чтобы не создавать замыкание на самого себя
                if remote_name in name_to_mac and name_to_mac[remote_name] != device['mac']:
                    connection['remote_mac'] = name_to_mac[remote_name]

    return data
    
class NetworkProcessor:
    def __init__(self, target=None, ip_list=None, mode='single'):
        self.target = target
        self.ip_list = ip_list
        self.mode = mode
        self.progress = 0

    def fetch_ip_addresses(self, target):
        ip_addresses = get_ip_adrss(target)

        addresses_to_remove = ['10.1.5.14', '10.1.5.10', '10.1.5.9', "10.1.5.13"]
        for address in addresses_to_remove:
            if address in ip_addresses:
                ip_addresses.remove(address)
        print (ip_addresses)
        return ip_addresses

    def update_progress(self, current, total):
        self.progress = int((current / total) * 100)

    def process_ip_addresses(self, ip_addresses):
        end = []
        total_ips = len(ip_addresses)

        with ThreadPoolExecutor(max_workers=21) as executor:
            futures = [executor.submit(fetch_info, ip) for ip in ip_addresses]
            for i, future in enumerate(futures):
                end.append(future.result())
                # print('1')
                self.update_progress(i + 1, total_ips)  # Обновление прогресса

        transformed_data = transform_data(end)
        processed_data = process_devices(transformed_data["devices"])
        cleaned_data0 = update_mac_addresses(processed_data)

        # cleaned_data00 = replace_mac_addresses(cleaned_data0, "02:eb:57:7c:c3:7f", "b8:69:f4:93:6b:7d")
        # cleaned_data000 = replace_mac_addresses(cleaned_data00, "34:0a:33:c8:af:a0", "34:0a:33:c8:af:b8")
        # cleaned_data0000 = replace_mac_addresses(cleaned_data000, "02:19:34:44:b8:84", "18:fd:74:8d:77:88")

        cleaned_data1 = process_device_data(cleaned_data0)
        filtered_data2 = clean_connections(cleaned_data1)
        filtered_data3 = clean_remote_mac(filtered_data2)
        print(json.dumps(filtered_data3, indent=4))
 
        return filtered_data3



    def save_results(self, data, target):
        # data = update_remote_macs(data1)
        # print(json.dumps(data, indent=4))

        
        
        
        if not data:
            raise ValueError("Data cannot be empty")

        router_ip = target
        router_mac = data[0]['mac']
        router_name = data[0]['name']
        update_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        fields_to_remove = ['remote_ip', 'remote_desc']
        cleaned_data = remove_fields(data, fields_to_remove)
        
        current_dir = os.path.dirname(__file__)
        links_dir = os.path.join(current_dir, 'links')
        if not os.path.exists(links_dir):
            os.makedirs(links_dir)
        
        db_path = os.path.join(links_dir, 'network_links.db')
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # Создание таблиц, если их еще нет
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS networks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                router_ip TEXT,
                router_mac TEXT,
                router_name TEXT,
                update_time TEXT
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS devices (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                networks_id INTEGER,
                device_ip TEXT,
                device_mac TEXT,
                device_name TEXT,
                FOREIGN KEY(networks_id) REFERENCES networks(id)
            )
        ''')

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS links (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                from_device_id INTEGER,
                from_port INTEGER,
                to_device_id INTEGER,
                to_port TEXT,
                FOREIGN KEY(from_device_id) REFERENCES devices(id),
                FOREIGN KEY(to_device_id) REFERENCES devices(id)
            )
        ''')

        # Вставка данных роутера в таблицу networks
        cursor.execute('''
            INSERT INTO networks (router_ip, router_mac, router_name, update_time)
            VALUES (?, ?, ?, ?)
        ''', (router_ip, router_mac, router_name, update_time))
        networks_id = cursor.lastrowid
        
        device_ids = {}  
        
        for item in cleaned_data:
            cursor.execute('''
                INSERT INTO devices (networks_id, device_ip, device_mac, device_name)
                VALUES (?, ?, ?, ?)
            ''', (networks_id, item['ip'], item['mac'], item['name']))
            device_id = cursor.lastrowid
            device_ids[item['mac']] = device_id

        # Вставка данных подключений в таблицу links
        for item in cleaned_data:
            from_device_id = device_ids[item['mac']]
            for port in item.get('ports', []):
                for connection in port.get('connections', []):
                    remote_port = connection['remote_port']
                    if isinstance(remote_port, list):
                        remote_port = ', '.join(remote_port)
                    
                    remote_mac = connection['remote_mac']
                    if remote_mac in device_ids:
                        to_device_id = device_ids[remote_mac]
                    else:
                        cursor.execute('''
                            INSERT INTO devices (networks_id, device_ip, device_mac, device_name)
                            VALUES (?, ?, ?, ?)
                        ''', (networks_id, connection.get('remote_ip', 'not found'), remote_mac, connection['remote_name']))
                        to_device_id = cursor.lastrowid
                        device_ids[remote_mac] = to_device_id

                    # Вставляем данные в таблицу links
                    cursor.execute('''
                        INSERT INTO links (from_device_id, from_port, to_device_id, to_port)
                        VALUES (?, ?, ?, ?)
                    ''', (
                        from_device_id,
                        port['port'],
                        to_device_id,
                        remote_port
                    ))

        conn.commit()
        conn.close()


    def run(self):
        if self.mode == 'single':
            target = self.target
            ip_addresses = self.fetch_ip_addresses(target)
            results = self.process_ip_addresses(ip_addresses)
            self.save_results(results, target)
        elif self.mode == 'list':
            ip_list = self.ip_list
            results = self.process_ip_addresses(ip_list)
            self.save_results(results)
        elif self.mode == 'auto':
            auto_target = '10.99.5.1'
            ip_addresses = self.fetch_ip_addresses(auto_target)
            results = self.process_ip_addresses(ip_addresses)
            self.save_results(results)