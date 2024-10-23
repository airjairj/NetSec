import argparse
from core import scanner, deauth, cracker, monitor_mode

def main():
    parser = argparse.ArgumentParser(description="Network Security Tool")
    subparsers = parser.add_subparsers(dest="command")

    # Scanner command
    parser_scanner = subparsers.add_parser("scan", help="Scan for networks")
    parser_scanner.add_argument("-i", "--interface", help="Network interface to use for scanning")

    # Deauth command
    parser_deauth = subparsers.add_parser("deauth", help="Perform deauthentication attack")
    parser_deauth.add_argument("-i", "--interface", required=True, help="Network interface to use for deauth attack")
    parser_deauth.add_argument("-t", "--target", required=True, help="Target MAC address")

    # Cracker command
    parser_cracker = subparsers.add_parser("crack", help="Crack WPA/WPA2 password")
    parser_cracker.add_argument("-i", "--interface", required=True, help="Network interface to use for cracking")
    parser_cracker.add_argument("-w", "--wordlist", required=True, help="Path to the wordlist file")

    # Monitor mode command
    parser_monitor = subparsers.add_parser("monitor", help="Set interface to monitor mode")
    parser_monitor.add_argument("-i", "--interface", required=True, help="Network interface to set to monitor mode")

    args = parser.parse_args()

    match args.command:
        case "scan":
            scanner.scan(args.interface)
        case "deauth":
            deauth.deauth_attack(args.interface, args.target)
        case "crack":
            cracker.crack(args.interface, args.wordlist)
        case "monitor":
            monitor_mode.set_monitor_mode(args.interface)
        case _:
            parser.print_help()

if __name__ == "__main__":
    main()