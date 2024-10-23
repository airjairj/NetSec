import pywifi
from pywifi import const
import time

def scan(interface=None):
    """
    Scans for networks using the specified network interface.
    If no interface is specified, the first available interface is used.
    
    Args:
        interface (str, optional): The network interface to use for scanning.
    """
    wifi = pywifi.PyWiFi()
    iface = None
    
    # List all available interfaces
    interfaces = wifi.interfaces()
    print("Available interfaces:")
    for i in interfaces:
        print(f" - {i.name()}")
    
    # Find the specified interface or use the first available one
    if interface:
        for i in interfaces:
            if i.name() == interface:
                iface = i
                break
        if iface is None:
            print(f"Interface {interface} not found.")
            return
    else:
        if interfaces:
            iface = interfaces[0]
        else:
            print("No interfaces available.")
            return
    
    iface.scan()
    time.sleep(5)  # Wait for the scan to complete
    results = iface.scan_results()
    
    for network in results:
        print(f"SSID: {network.ssid}, Signal: {network.signal}, BSSID: {network.bssid}")

# Example usage:
# scan("Wi-Fi")
# scan()  # Automatically picks the first available interface