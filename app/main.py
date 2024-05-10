from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Depends
import psutil
import asyncio 
from typing import List
from collections import defaultdict
from websockets.exceptions import ConnectionClosedOK
import re
from fastapi.middleware.cors import CORSMiddleware
from scapy.all import sniff, ARP, Ether, srp ,sniff, IP, TCP, ICMP, UDP, AsyncSniffer
from typing import Dict
import json
import threading
import time
from queue import Queue
import numpy as np

packet_counts = defaultdict(int)
intervals = {}
last_packet_time = defaultdict(float)
packet_counts_lock = threading.Lock()
intervals_lock = threading.Lock()
last_packet_time_lock = threading.Lock()

# WebSocket connections for /ws/log endpoint
log_websocket_connections: List[WebSocket] = []


class Rule:
    def __init__(self, name: str, rule_type: str, conditions: Dict[str, str], action: str):
        self.name = name
        self.rule_type = rule_type
        self.conditions = conditions
        self.action = action

with open("app/rule.json") as f:
    rules_data = json.load(f)
    rules = [Rule(**rule) for rule in rules_data]

active_connections: List = []

async def evaluate_rules(packet):
    if packet.haslayer(IP):
        source_ip = packet[IP].src
        arrival_time = packet.time
        jitter = calculate_jitter(source_ip, arrival_time)
    else:
        source_ip = None
        arrival_time = packet.time
        jitter = None

    # Determine the type of request
    request_type = "Unknown"
    if TCP in packet:
        if packet[TCP].flags.S:
            request_type = "SYN"
        elif packet[TCP].flags.A and packet[TCP].flags.P:
            request_type = "HTTP"
        elif packet[TCP].flags.F:
            request_type = "FIN"
        elif packet[TCP].flags.R:
            request_type = "RST"
        elif UDP in packet:
            request_type = "UDP"
        elif ICMP in packet:
            request_type = "ICMP"

    matched_events = []
    
    for rule in rules:
        conditions_met = all(check_condition(packet, key, value) for key, value in rule.conditions.items())
        if conditions_met:
            event = {"packet": str(packet), "rule": rule.name, "action": rule.action, "type": rule.rule_type,"source_ip": source_ip,"request_type": request_type,"jitter": jitter}
            matched_events.append(event)
    if not matched_events:
        # Add a default event when no matches are found
        default_event = {"packet": str(packet), "rule": "Log", "action": "Monitoring", "type": "Log","source_ip": source_ip,"request_type": request_type,"jitter": jitter}
        for websocket in log_websocket_connections:
            try:
                await websocket.send_json(default_event)
            except ConnectionClosedOK:
                log_websocket_connections.remove(websocket)
    else:
        # Send matched events to the WebSocket
        for websocket in log_websocket_connections:
            try:
                for event in matched_events:
                    await websocket.send_json(event)
            except ConnectionClosedOK:
                log_websocket_connections.remove(websocket)
        

def send_event_to_ws_logs(event):
    # Loop through each active WebSocket connection
    for connection in active_connections:
        try:
            # Send the event data to the WebSocket client
            connection.send_json(event)
        except Exception as e:
            # Handle any exceptions that occur during sending
            print(f"Error occurred while sending event: {e}")

# Function to check conditions against packet attributes
def check_condition(packet, key, value):
    if key == "packet_rate":
        # Check packet rate from a single IP
        src_ip = packet.src
        with packet_counts_lock:
            packet_count = packet_counts.get(src_ip, 0)
            packet_counts[src_ip] = packet_count + 1
            last_time = last_packet_time.get(src_ip, time.time())
            last_packet_time[src_ip] = time.time()
        elapsed_time = time.time() - last_time if last_time else 0.1  # To avoid division by zero

        # Ensure that elapsed_time is not zero
        elapsed_time = max(elapsed_time, 0.1)
        
        # Extract the operator and threshold from the value string
        operator, threshold = value[0], value[1:]
        
        # Evaluate the condition based on the operator
        if operator == '<':
            return packet_count / elapsed_time < int(threshold)
        elif operator == '>':
            return packet_count / elapsed_time > int(threshold)
        elif operator == '==':
            return packet_count / elapsed_time == int(threshold)
        elif operator == '!=':
            return packet_count / elapsed_time != int(threshold)
        elif operator == '<=':
            return packet_count / elapsed_time <= int(threshold)
        elif operator == '>=':
            return packet_count / elapsed_time >= int(threshold)
        else:
            # Handle other comparison operators as needed
            return False
    elif key == "flags":
        # Check TCP flags (e.g., "S" for SYN)
        if TCP in packet:
            return packet[TCP].flags & TCP.flags[value] != 0
        else:
            return False
    elif key == "payload_length":
        # Check packet payload length
        if IP in packet:
            # Split the value into operator and threshold
            operator, threshold = value[0], value[1:]
            if operator == '<':
                return len(packet[IP].payload) < int(threshold)
            elif operator == '>':
                return len(packet[IP].payload) > int(threshold)
            else:
                # Handle other comparison operators as needed
                return False
        else:
            return False
    else:
        # Check other packet attributes (e.g., protocol)
        return getattr(packet, key, None) == value


# DDoS detection threshold
DDOS_THRESHOLD = 1000
# Jitter threshold (adjust as needed)
JITTER_THRESHOLD = 0.5

# Dictionary to store packet counts for each source IP
packet_counts = defaultdict(int)
# Dictionary to store packet arrival times for each source IP
packet_arrival_times = defaultdict(list)


def calculate_jitter(source_ip, arrival_time):
    packet_arrival_times[source_ip].append(arrival_time)
    inter_arrival_times = np.diff(packet_arrival_times[source_ip])
    if len(inter_arrival_times) <= 1:
        return 0  # No jitter if there's only one packet
    jitter = np.std(inter_arrival_times)
    return jitter if not np.isnan(jitter) else 0

def update_intervals():
    while True:
        current_time = time.time()
        ips_to_remove = []
        with intervals_lock:
            with last_packet_time_lock:
                for ip, last_time in last_packet_time.items():
                    if current_time - last_time > 420:  # If inactive for more than 7 minutes
                        ips_to_remove.append(ip)
                for ip in ips_to_remove:
                    if ip in intervals:
                        del intervals[ip]
        time.sleep(30)  # Check every 30 seconds

# Create a queue to store packets
packet_queue = Queue()

def packet_sniffer_logs():
    def process_packet(packet):
        asyncio.run(_process_packet(packet))

    async def _process_packet(packet):
        await evaluate_rules(packet)
        
            

    sniff(iface='Intel(R) Wireless-AC 9560 160MHz', prn=process_packet, store=0)



def packet_sniffer_traffic():
    def process_packet(packet):
        if packet.haslayer(IP):
            ip_src = packet[IP].src
            with packet_counts_lock:
                packet_counts[ip_src] = packet_counts.get(ip_src, 0) + 1
            with last_packet_time_lock:
                last_packet_time[ip_src] = time.time()
            
    # Start sniffing packets
    sniff(iface='Intel(R) Wireless-AC 9560 160MHz',prn=process_packet, store=0)

  


def send_packet_counts(websockets):
    while True:
        with packet_counts_lock:
            top_10_ip_counts = sorted(packet_counts.items(), key=lambda x: x[1], reverse=True)[:10]
        active_ips = set(ip for ip, _ in top_10_ip_counts)

        with intervals_lock:
            for ip, counts in top_10_ip_counts:
                if ip in active_ips:
                    if isinstance(counts, list) and len(counts) < 7:
                        continue
                    interval_list = intervals.setdefault(ip, [])
                    if len(interval_list) == 7:
                        interval_list.pop(0)
                    interval_list.append(counts)
                    packet_counts[ip] = 0

        time.sleep(30)

app = FastAPI()

@app.on_event("startup")
async def startup_event():
    sniffing_thread_logs = threading.Thread(target=packet_sniffer_logs)
    sniffing_thread_logs.daemon = True
    sniffing_thread_logs.start()
    
    sniffing_thread_traffic = threading.Thread(target=packet_sniffer_traffic)
    sniffing_thread_traffic.daemon = True
    sniffing_thread_traffic.start()
    
    app.state.websockets = set()

    send_thread = threading.Thread(target=send_packet_counts, args=(app.state.websockets,))
    send_thread.daemon = True
    send_thread.start()

    interval_thread = threading.Thread(target=update_intervals)
    interval_thread.daemon = True
    interval_thread.start()

@app.websocket("/ws_logs")
async def websocket_endpoint(websocket: WebSocket):
    # Accept the WebSocket connection
    await websocket.accept()

    active_connections.append(websocket)
    try:
        while True:
            await asyncio.sleep(1)
    except Exception as e:
        print("WebSocket error:", e)
    finally:
        # Remove the connection from the list of active connections when it's closed
        active_connections.remove(websocket)
    await websocket.close()



async def send_bandwidth_data(websocket: WebSocket):
    try:
        while True:
            net_io = psutil.net_io_counters()
            bytes_sent = net_io.bytes_sent
            bytes_recv = net_io.bytes_recv

            await websocket.send_json({'bytes_sent': bytes_sent, 'bytes_recv': bytes_recv})

            # Sleep for 1 second
            await asyncio.sleep(1)
    except WebSocketDisconnect:
        # Handle WebSocket disconnect
        print("WebSocket disconnected")



async def get_top_network_services() -> Dict[str, int]:
    connections = psutil.net_connections()
    services_count = {}
    for conn in connections:
        if conn.pid is not None and conn.status == "ESTABLISHED":
            pid = conn.pid
            try:
                service_name = psutil.Process(pid).name()
                services_count[service_name] = services_count.get(service_name, 0) + 1
            except psutil.NoSuchProcess:
                pass
    top_services = dict(sorted(services_count.items(), key=lambda x: x[1], reverse=True)[:5])
    return top_services

def scan_network(ip_range):
    arp_request = ARP(pdst=ip_range)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    
    devices = []
    for element in answered_list:
        device = {"ip": element[1].psrc, "mac": element[1].hwsrc}
        devices.append(device)
    return devices

@app.websocket("/ws/log")
async def websocket_log_endpoint(websocket: WebSocket):
    await websocket.accept()
    log_websocket_connections.append(websocket)
    try:
        while True:
            # Send DDoS detection messages to the WebSocket client
            data = await websocket.receive_text()
            await websocket.send_text(f"{data}")
    except Exception as e:
        print("WebSocket error:", e)
    finally:
        # Remove the connection from the list of log_websocket_connections connections when it's closed
        log_websocket_connections.remove(websocket)
        await websocket.close()

@app.get("/network/devices/")
def get_connected_devices(ip_range: str = "192.168.1.0/24"):
    """
    Get the count of all devices connected to the network
    :param ip_range: IP range to scan (default is 192.168.1.0/24)
    :return: List of devices with IP and MAC addresses
    """
    devices = scan_network(ip_range)
    return {"total_devices": len(devices), "devices": devices}


@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):

    # Accept the WebSocket connection
    await websocket.accept()

    # Start sending bandwidth data
    await send_bandwidth_data(websocket)
   

@app.websocket("/ws_top_services")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    try:
        while True:
            top_services = await get_top_network_services()
            await websocket.send_json({"top_services": top_services})
            await asyncio.sleep(5)  # Update every 5 seconds
    except Exception as e:
        print("WebSocket error:", e)
    finally:
        await websocket.close()

@app.websocket("/ws/traffic")
async def websocket_traffic(websocket: WebSocket):
    await websocket.accept()
    try:
        while True:
            top_10_intervals = {}
            with intervals_lock:
                top_10_ip_counts = sorted(intervals.items(), key=lambda x: sum(x[1]), reverse=True)[:10]
                for ip, interval_list in top_10_ip_counts:
                    top_10_intervals[ip] = interval_list + [0] * (7 - len(interval_list))
            
            # Prepare the data to send
            data = [{"name": ip, "data": interval_list} for ip, interval_list in top_10_intervals.items()]

            # Send the data to the WebSocket client
            await websocket.send_text(json.dumps(data))

            # Sleep for a short interval before sending the next update
            await asyncio.sleep(5)  # Adjust as needed
    except WebSocketDisconnect:
        pass



origins = ["*"]
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)