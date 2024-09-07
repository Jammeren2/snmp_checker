# network_utils.py

import networkx as nx
import os
import sqlite3

def is_number(s):
    try:
        float(s)
        return True
    except ValueError:
        return False
def extract_port(port):
    """
    Извлекает порт из строки вида 'ethX/Y/port'. 
    Если строка имеет другой формат, возвращает её без изменений.
    """
    if isinstance(port, str) and port.startswith('eth'):
        parts = port.split('/')
        if len(parts) > 2:
            return parts[-1]
    return port
def get_update_dates(router_ip):
    current_dir = os.path.dirname(__file__)
    db_path = os.path.join(current_dir, 'links', 'network_links.db')
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    cursor.execute('''
        SELECT DISTINCT update_time
        FROM networks
        WHERE router_ip = ?
        ORDER BY update_time DESC
    ''', (router_ip,))
    dates = [row[0] for row in cursor.fetchall()]

    conn.close()
    return dates

def get_data_for_update_time(update_time):
    current_dir = os.path.dirname(__file__)
    db_path = os.path.join(current_dir, 'links', 'network_links.db')
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM networks WHERE update_time = ?", (update_time,))
    networks = cursor.fetchall()

    network_ids = [network[0] for network in networks]

    devices = {}
    for network_id in network_ids:
        cursor.execute("SELECT * FROM devices WHERE networks_id = ?", (network_id,))
        for device in cursor.fetchall():
            devices[device[4]] = device  # Use device_ip as the key

    links = []
    for network_id in network_ids:
        cursor.execute("""
            SELECT 
                l.id, 
                d1.device_ip AS from_device_ip, 
                l.from_port, 
                d2.device_ip AS to_device_ip, 
                l.to_port 
            FROM links l
            JOIN devices d1 ON l.from_device_id = d1.id
            JOIN devices d2 ON l.to_device_id = d2.id
            WHERE d1.networks_id = ? AND d2.networks_id = ?
        """, (network_id, network_id))
        links.extend(cursor.fetchall())

    conn.close()

    return {
        'devices': devices,
        'links': links
    }

def find_differences(data1, data2):
    differences = {'devices': {'added': [], 'removed': []}, 'links': {'added': [], 'removed': []}}

    # Compare devices
    set1 = set(data1['devices'].keys())
    set2 = set(data2['devices'].keys())

    added_devices = set2 - set1
    removed_devices = set1 - set2

    differences['devices']['added'] = [data2['devices'][ip] for ip in added_devices]
    differences['devices']['removed'] = [data1['devices'][ip] for ip in removed_devices]

    # Compare links
    set1 = set((link[1], link[2], link[3], link[4]) for link in data1['links'])
    set2 = set((link[1], link[2], link[3], link[4]) for link in data2['links'])

    added_links = set2 - set1
    removed_links = set1 - set2

    differences['links']['added'] = [link for link in data2['links'] if (link[1], link[2], link[3], link[4]) in added_links]
    differences['links']['removed'] = [link for link in data1['links'] if (link[1], link[2], link[3], link[4]) in removed_links]

    return differences

def load_data_and_create_graph(update_time):
    current_dir = os.path.dirname(__file__)
    db_path = os.path.join(current_dir, 'links', 'network_links.db')


    '''
    эта залупа удаляет remote_ip not found
    '''
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    # Шаг 0: Получаем все устройства с device_ip = 'not found'
    cursor.execute("SELECT id, device_mac FROM devices WHERE device_ip = 'not found'")
    false_devices = cursor.fetchall()
    
    for false_device in false_devices:
        false_id, false_mac = false_device
        
        # Шаг 1: Берем device_mac xx:xx:xx:xx:xy:yy и оставляем xx:xx:xx:xx:x
        partial_mac = ':'.join(false_mac.split(':')[:-1])
        
        # Шаг 2: Ищем совпадения по device_mac
        cursor.execute("SELECT id, device_ip FROM devices WHERE device_mac LIKE ? AND id != ?", (partial_mac + '%', false_id))
        matching_devices = cursor.fetchall()
        
        for matching_device in matching_devices:
            orig_id, orig_ip = matching_device
            
            # Шаг 4: Проверяем, что это не то же самое устройство с device_ip = 'not found'
            if orig_ip != 'not found':
                # Шаг 5: Запоминаем id этого устройства как orig_id
                # Шаг 6: Обновляем таблицу links, меняем все false_id на orig_id
                cursor.execute("UPDATE links SET from_device_id = ? WHERE from_device_id = ?", (orig_id, false_id))
                cursor.execute("UPDATE links SET to_device_id = ? WHERE to_device_id = ?", (orig_id, false_id))
                conn.commit()
                
    # Шаг 7: Удаляем устройства с device_ip = 'not found'
    cursor.execute("DELETE FROM devices WHERE device_ip = 'not found'")
    conn.commit()
    
    conn.close()
    '''
    эта залупа закончилась
    '''
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    G = nx.MultiGraph()
    cursor.execute('SELECT id FROM networks WHERE update_time = ?', (update_time,))
    networks_id = cursor.fetchall()[0][0]

    cursor.execute('SELECT device_ip, device_mac, device_name FROM devices WHERE networks_id = ?', (networks_id,))
    devices = cursor.fetchall()

    device_info_map = {}
    for device in devices:
        device_ip, device_mac, device_name = device
        device_info = f"{device_name}\n{device_ip}\n{device_mac}"
        device_info_map[device_mac] = device_name
        label2 = f"{device_ip}\n{device_name}"
        G.add_node(device_mac, label=device_info, label2=label2, color='lightblue')

    cursor.execute('''
        SELECT d1.device_mac, l.from_port, d2.device_mac, l.to_port
        FROM links l
        JOIN devices d1 ON l.from_device_id = d1.id
        JOIN devices d2 ON l.to_device_id = d2.id
        JOIN networks n ON d1.networks_id = n.id
        WHERE n.id = ?
    ''', (networks_id,))
    links = cursor.fetchall()

    for link in links:
        from_mac, from_port, to_mac, to_port = link
        from_device_name = device_info_map.get(from_mac, "Unknown")
        to_device_name = device_info_map.get(to_mac, "Unknown")
        G.add_edge(
            from_mac, to_mac, 
            label=f"{from_device_name}: {from_port} <--> {to_device_name}: {to_port}", 
            color='grey',
            from_port=from_port, 
            to_port=to_port
        )

    nodes_to_remove = [node for node, data in G.nodes(data=True) if 'label' not in data or data['label'] == 'No label']
    for node in nodes_to_remove:
        neighbors = list(G.neighbors(node))
        if len(neighbors) > 1:
            for i in range(len(neighbors)):
                for j in range(i + 1, len(neighbors)):
                    edge_label = "0 <--> 0"
                    G.add_edge(neighbors[i], neighbors[j], label=edge_label)
        G.remove_node(node)

    pos = nx.kamada_kawai_layout(G)
    scale_factor = 1100 if len(G.nodes) > 26 else 700 if len(G.nodes) > 20 else 500
    scaled_pos = {node: (pos[node][0] * scale_factor, pos[node][1] * scale_factor) for node in G.nodes()}

    nodes = []
    for node, data in G.nodes(data=True):
        nodes.append({
            'data': {
                'id': node,
                'label': data.get('label', 'No label'),
                'label2': data.get('label2', ''),
                'color': data.get('color', 'lightblue')
            },
            'position': {'x': scaled_pos[node][0], 'y': scaled_pos[node][1]}
        })

    edges = []
    seen_edges = set()
    for source, target, data in G.edges(data=True):
        # Получаем информацию об устройствах и портах
        from_device = device_info_map.get(source, "Unknown")
        to_device = device_info_map.get(target, "Unknown")
        from_port = extract_port(data['from_port'])
        to_port = extract_port(data['to_port'])

        # Приводим порты к строкам для сортировки и сравнения
        from_port_str = str(from_port)
        to_port_str = str(to_port)

        # Создаем ключ для уникальности, учитывающий переворот устройств и портов
        sorted_devices_ports = sorted([
            (from_device, from_port_str),
            (to_device, to_port_str)
        ], key=lambda x: (x[0], x[1]))

        sorted_label = ' <--> '.join([f"{dev}: {port}" for dev, port in sorted_devices_ports])
        sorted_edge = tuple(sorted((source, target)))
        sorted_ports = tuple(sorted([from_port_str, to_port_str]))
        edge_key = (sorted_edge, sorted_ports)

        # Добавляем ребро, если его еще нет в seen_edges
        if edge_key not in seen_edges:
            seen_edges.add(edge_key)
            edges.append({
                'data': {
                    'source': source,
                    'target': target,
                    'label': sorted_label,
                    'label2': f'{sorted_ports[0]} <--> {sorted_ports[1]}',
                    'color': data.get('color', 'grey'),
                    'from_port': from_port_str,
                    'to_port': to_port_str
                }
            })


    conn.close()
    return nodes + edges
