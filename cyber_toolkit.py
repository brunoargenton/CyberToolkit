import hashlib
import base64
import socket
import logging
import ipaddress

# Logging configuration
logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(message)s')


# === Utility functions ===

def hash_text(text: str):
    """Return MD5, SHA1, and SHA256 hashes of the given text."""
    return {algo.upper(): getattr(hashlib, algo)(text.encode()).hexdigest()
            for algo in ('md5', 'sha1', 'sha256')}


def base64_encode(text: str) -> str:
    return base64.b64encode(text.encode()).decode()


def base64_decode(text: str) -> str:
    return base64.b64decode(text.encode()).decode()


def port_scanner(target: str, start: int, end: int, timeout=0.5):
    """Scan a range of TCP ports on a target host."""
    open_ports = []
    for port in range(start, end + 1):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            if s.connect_ex((target, port)) == 0:
                open_ports.append(port)
    return open_ports


def get_local_ip():
    """Get the local IP address of the machine running this script."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
    except Exception as e:
        print("❌ Failed to get local IP address:", e)
        return None


def scan_home_assistant_network(port=8123, timeout=0.5):
    """Scan the local /24 network for devices with port 8123 open (Home Assistant)."""
    local_ip = get_local_ip()
    if not local_ip:
        print("❌ Could not detect local IP address.")
        return

    net_base = '.'.join(local_ip.split('.')[:3]) + '.0/24'
    network = ipaddress.IPv4Network(net_base, strict=False)

    print(f"\n🔍 Scanning network {network} on port {port}...\n")

    for ip in network.hosts():
        ip_str = str(ip)
        try:
            with socket.create_connection((ip_str, port), timeout=timeout):
                print(f"✅ {ip_str}:{port} is OPEN (Home Assistant likely running)")
        except (socket.timeout, ConnectionRefusedError):
            print(f"❌ {ip_str}:{port} is closed")
        except socket.gaierror:
            print(f"⚠️ Could not resolve {ip_str}")


# === Interactive Menu ===

def menu():
    while True:
        print("\n=== Simple Cybersecurity Toolkit ===")
        print("1) Hash Text")
        print("2) Base64 Encode/Decode")
        print("3) Port Scanner")
        print("4) Scan Local Network for Home Assistant (port 8123)")
        print("5) Exit")
        choice = input("Select an option: ").strip()

        if choice == '1':
            text = input("Enter text to hash: ")
            hashes = hash_text(text)
            for algo, digest in hashes.items():
                print(f"{algo}: {digest}")

        elif choice == '2':
            text = input("Enter text: ")
            action = input("Encode (E) or Decode (D)? ").strip().lower()
            try:
                if action == 'e':
                    print("Encoded:", base64_encode(text))
                elif action == 'd':
                    print("Decoded:", base64_decode(text))
                else:
                    print("Invalid option.")
            except base64.binascii.Error as e:
                logging.error("Invalid Base64 input. Error: %s", e)

        elif choice == '3':
            target = input("Enter target IP or hostname: ").strip()
            port_range = input("Enter port range (start-end, e.g., 20-1024): ").strip()
            try:
                start, end = map(int, port_range.split('-'))
            except ValueError:
                print("Invalid range. Using default 1-1024.")
                start, end = 1, 1024
            print(f"Scanning {target} from port {start} to {end}...")
            open_ports = port_scanner(target, start, end)
            if open_ports:
                for port in open_ports:
                    print(f"Port {port} is open")
            else:
                print("No open ports found in the specified range.")

        elif choice == '4':
            scan_home_assistant_network()

        elif choice == '5':
            print("Goodbye!")
            break

        else:
            print("Invalid option. Please try again.")


if __name__ == '__main__':
    menu()
