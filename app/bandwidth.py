import psutil
import time

def calculate_bandwidth(interval=1):
    while True:
        net_io = psutil.net_io_counters()
        bytes_sent = net_io.bytes_sent
        bytes_recv = net_io.bytes_recv

        # Sleep for the specified interval
        time.sleep(interval)

        # Get new network stats after the interval
        new_net_io = psutil.net_io_counters()
        new_bytes_sent = new_net_io.bytes_sent
        new_bytes_recv = new_net_io.bytes_recv

        # Calculate bandwidth in bits per second
        sent_bandwidth = (new_bytes_sent - bytes_sent) * 8 / interval
        recv_bandwidth = (new_bytes_recv - bytes_recv) * 8 / interval

        print(f"Sent bandwidth: {sent_bandwidth} bits/s, Received bandwidth: {recv_bandwidth} bits/s")

if __name__ == "__main__":
    calculate_bandwidth()
