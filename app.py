# app.py
import os
import sqlite3
from flask import Flask, jsonify, render_template, request
from topology_sqlite import NetworkProcessor
from network_utils import (
    is_number,
    get_update_dates,
    get_data_for_update_time,
    find_differences,
    load_data_and_create_graph
)

app = Flask(__name__)

@app.route('/')
def index():
    current_dir = os.path.dirname(__file__)
    db_path = os.path.join(current_dir, 'links', 'network_links.db')
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    cursor.execute('''
        SELECT n.id, n.router_name, n.router_ip, n.update_time
        FROM networks n
        INNER JOIN (
            SELECT router_ip, MAX(update_time) AS latest_update
            FROM networks
            GROUP BY router_ip
        ) latest_networks
        ON n.router_ip = latest_networks.router_ip AND n.update_time = latest_networks.latest_update
    ''')
    networks = cursor.fetchall()

    conn.close()
    file_names = [{'router_ip': network[2], 'dates': get_update_dates(network[2])} for network in networks]
    return render_template('index.html', files=file_names)

@app.route('/sop', methods=['POST'])
def sop():
    sop1 = request.json.get('sop1')
    sop2 = request.json.get('sop2')

    data1 = get_data_for_update_time(sop1)
    data2 = get_data_for_update_time(sop2)

    differences = find_differences(data1, data2)

    return jsonify(differences)

@app.route('/del_by_data', methods=['POST'])
def del_by_data():
    try:
        update_time = request.json.get('data')
        old = request.json.get('old', False)
        current_dir = os.path.dirname(__file__)
        links_dir = os.path.join(current_dir, 'links')
        db_path = os.path.join(links_dir, 'network_links.db')
        
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()

        if old:
            cursor.execute("SELECT id FROM networks WHERE update_time < ?", (update_time,))
        else:
            cursor.execute("SELECT id FROM networks WHERE update_time = ?", (update_time,))

        networks_to_delete = cursor.fetchall()
        if not networks_to_delete:
            return jsonify({"status": "unsuccess"})
        for network in networks_to_delete:
            print(network)
            network_id = network[0]
            cursor.execute("SELECT id FROM devices WHERE networks_id = ?", (network_id,))
            devices_to_delete = cursor.fetchall()
            for device in devices_to_delete:
                device_id = device[0]
                cursor.execute("DELETE FROM links WHERE from_device_id = ? OR to_device_id = ?", (device_id, device_id))
            cursor.execute("DELETE FROM devices WHERE networks_id = ?", (network_id,))
            cursor.execute("DELETE FROM networks WHERE id = ?", (network_id,))

        conn.commit()
        return jsonify({"status": "success"})
    except sqlite3.Error as e:
        print(f"An error occurred: {e}")
        if conn:
            conn.rollback()
        return jsonify({"status": "unsuccess"})
    finally:
        if conn:
            conn.close()

@app.route('/update_graph', methods=['POST'])
def update_graph():
    file_name = request.json.get('file_name')
    networks_date = file_name.split('(')[-1].strip(')')

    updated_elements = load_data_and_create_graph(networks_date)
    
    return jsonify(updated_elements)

@app.route('/update_data', methods=['POST'])
def update_data():
    file_name = request.json.get('file_name')

    np_single = NetworkProcessor(target=file_name, mode='single')
    np_single.run()

    return jsonify({"status": "success"})

@app.route('/add_file', methods=['POST'])
def add_file():
    data = request.json
    ip = data.get('ip')

    np_single = NetworkProcessor(target=ip, mode='single')
    np_single.run()

    return jsonify({"status": "success"})

if __name__ == '__main__':
    app.run(debug=True,
        # host = '0.0.0.0',
         port=8889)
