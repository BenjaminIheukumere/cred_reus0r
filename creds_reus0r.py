#!/usr/bin/env python3
import sys
import os
import ipaddress
import getpass
import socket
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from tqdm import tqdm

# ---------- Optional deps ----------
try:
    import paramiko
    HAS_PARAMIKO = True
except Exception:
    HAS_PARAMIKO = False

try:
    from ldap3 import Server, Connection, SIMPLE, NONE, Tls
    HAS_LDAP3 = True
except Exception:
    HAS_LDAP3 = False

try:
    import winrm  # needs requests-ntlm under the hood
    HAS_PYWINRM = True
except Exception:
    HAS_PYWINRM = False

try:
    import pymssql
    HAS_PYMSSQL = True
except Exception:
    HAS_PYMSSQL = False

from impacket.smbconnection import SMBConnection
from ftplib import FTP, error_perm

# ---------- Colors ----------
class C:
    HEADER   = '\033[95m'
    OKBLUE   = '\033[94m'
    OKCYAN   = '\033[96m'
    OKGREEN  = '\033[92m'
    WARNING  = '\033[93m'
    FAIL     = '\033[91m'
    BOLD     = '\033[1m'
    RESET    = '\033[0m'
    WHITE    = '\033[37m'

# ---------- UI ----------
def clear_screen():
    os.system('clear' if os.name == 'posix' else 'cls')

def banner():
    art = r"""
  /$$$$$$                            /$$                 /$$$$$$$                                 /$$$$$$           
 /$$__  $$                          | $$                | $$__  $$                               /$$$_  $$          
| $$  \__/  /$$$$$$   /$$$$$$   /$$$$$$$  /$$$$$$$      | $$  \ $$  /$$$$$$  /$$   /$$  /$$$$$$$| $$$$\ $$  /$$$$$$ 
| $$       /$$__  $$ /$$__  $$ /$$__  $$ /$$_____/      | $$$$$$$/ /$$__  $$| $$  | $$ /$$_____/| $$ $$ $$ /$$__  $$
| $$      | $$  \__/| $$$$$$$$| $$  | $$|  $$$$$$       | $$__  $$| $$$$$$$$| $$  | $$|  $$$$$$ | $$\ $$$$| $$  \__/
| $$    $$| $$      | $$_____/| $$  | $$ \____  $$      | $$  \ $$| $$_____/| $$  | $$ \____  $$| $$ \ $$$| $$      
|  $$$$$$/| $$      |  $$$$$$$|  $$$$$$$ /$$$$$$$/      | $$  | $$|  $$$$$$$|  $$$$$$/ /$$$$$$$/|  $$$$$$/| $$      
 \______/ |__/       \_______/ \_______/|_______/       |__/  |__/ \_______/ \______/ |_______/  \______/ |__/      

"""
    print(f"{C.OKCYAN}")
    print(art)

def print_imprint():
    imprint = r"""
                                           Creds Reus0r v1.0
                                 by Benjamin Iheukumere | SafeLink IT
                                    b.iheukumere@safelink-it.com
"""	
    print(f"{C.OKBLUE}")
    print(imprint)
    print(f"{C.RESET}")

# ---------- Helpers ----------
ANSI_RE = re.compile(r'\x1b\[[0-9;]*m')

def visible_len(s: str) -> int:
    return len(ANSI_RE.sub('', s))

def render_table(rows, headers):
    cols = len(headers)
    widths = [visible_len(h) for h in headers]
    for r in rows:
        for i in range(cols):
            widths[i] = max(widths[i], visible_len(str(r[i])))

    def hline():
        return "+" + "+".join("-" * (w + 2) for w in widths) + "+"

    def row(items):
        cells = []
        for i in range(cols):
            cell = str(items[i])
            pad = widths[i] + (len(cell) - visible_len(cell))
            cells.append(" " + cell.ljust(pad) + " ")
        return "|" + "|".join(cells) + "|"

    lines = [hline(), row(headers), hline()]
    for r in rows:
        lines.append(row(r))
        lines.append(hline())
    return "\n".join(lines)

def port_open(ip: str, port: int, timeout=1.5) -> bool:
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except Exception:
        return False

# ---------- Service checks ----------
def check_smb(ip: str, username: str, password: str):
    try:
        if not port_open(ip, 445):
            return ("SMB", False, "TCP/445 closed")
        conn = SMBConnection(ip, ip, sess_port=445, timeout=3)
        if username:
            if "\\" in username:
                domain, user = username.split("\\", 1)
            else:
                domain, user = '', username
            conn.login(user, password, domain)
        else:
            conn.login('', '')  # anonymous
        conn.logoff()
        return ("SMB", True, "Authentication succeeded")
    except Exception:
        return ("SMB", False, "Auth failed")

def check_ssh(ip: str, username: str, password: str):
    if not HAS_PARAMIKO:
        return ("SSH", False, "Paramiko not installed")
    if not username:
        return ("SSH", False, "Username required")
    if not port_open(ip, 22):
        return ("SSH", False, "TCP/22 closed")
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(ip, port=22, username=username, password=password,
                       timeout=3, auth_timeout=3, banner_timeout=3)
        client.close()
        return ("SSH", True, "Authentication succeeded")
    except Exception:
        return ("SSH", False, "Auth failed")

def check_ftp(ip: str, username: str, password: str):
    if not port_open(ip, 21):
        return ("FTP", False, "TCP/21 closed")
    try:
        with FTP() as ftp:
            ftp.connect(ip, 21, timeout=3)
            if username:
                ftp.login(user=username, passwd=password)
            else:
                ftp.login()  # anonymous
            try:
                ftp.nlst()
            except error_perm:
                pass
            return ("FTP", True, "Authentication succeeded")
    except Exception:
        return ("FTP", False, "Auth failed")

def _ldap_bind(ip: str, username: str, password: str, port: int, use_ssl: bool):
    if not HAS_LDAP3:
        return (f"LD{'APS' if use_ssl else 'AP'}", False, "ldap3 not installed")
    if not port_open(ip, port):
        return (f"LD{'APS' if use_ssl else 'AP'}", False, f"TCP/{port} closed")
    try:
        server = Server(ip, port=port, use_ssl=use_ssl, get_info=NONE)
        if username:
            conn = Connection(server, user=username, password=password,
                              authentication=SIMPLE, receive_timeout=3, auto_bind=True)
        else:
            # anonymous bind attempt
            conn = Connection(server, receive_timeout=3, auto_bind=True)
        conn.unbind()
        return (f"LD{'APS' if use_ssl else 'AP'}", True, "Bind succeeded")
    except Exception:
        return (f"LD{'APS' if use_ssl else 'AP'}", False, "Bind failed")

def check_ldap(ip: str, username: str, password: str):
    return _ldap_bind(ip, username, password, 389, use_ssl=False)

def check_ldaps(ip: str, username: str, password: str):
    return _ldap_bind(ip, username, password, 636, use_ssl=True)

def check_ldap_gc(ip: str, username: str, password: str):
    return _ldap_bind(ip, username, password, 3268, use_ssl=False)

def check_ldaps_gc(ip: str, username: str, password: str):
    return _ldap_bind(ip, username, password, 3269, use_ssl=True)

def check_winrm_http(ip: str, username: str, password: str):
    if not HAS_PYWINRM:
        return ("WinRM-HTTP", False, "pywinrm not installed")
    if not username:
        return ("WinRM-HTTP", False, "Username required")
    if not port_open(ip, 5985):
        return ("WinRM-HTTP", False, "TCP/5985 closed")
    try:
        s = winrm.Session(f'http://{ip}:5985', auth=(username, password))  # transport auto-negotiates
        r = s.run_cmd('whoami')
        if r.status_code == 0:
            return ("WinRM-HTTP", True, "Authentication succeeded")
        return ("WinRM-HTTP", False, f"Non-zero status: {r.status_code}")
    except Exception:
        return ("WinRM-HTTP", False, "Auth failed")

def check_winrm_https(ip: str, username: str, password: str):
    if not HAS_PYWINRM:
        return ("WinRM-HTTPS", False, "pywinrm not installed")
    if not username:
        return ("WinRM-HTTPS", False, "Username required")
    if not port_open(ip, 5986):
        return ("WinRM-HTTPS", False, "TCP/5986 closed")
    try:
        s = winrm.Session(f'https://{ip}:5986', auth=(username, password),
                          server_cert_validation='ignore')
        r = s.run_cmd('whoami')
        if r.status_code == 0:
            return ("WinRM-HTTPS", True, "Authentication succeeded")
        return ("WinRM-HTTPS", False, f"Non-zero status: {r.status_code}")
    except Exception:
        return ("WinRM-HTTPS", False, "Auth failed")

def check_rdp(ip: str, username: str, password: str):
    # Proper RDP auth check needs extra libs (e.g., rdpy or custom CredSSP). We indicate capability.
    if not port_open(ip, 3389):
        return ("RDP", False, "TCP/3389 closed")
    return ("RDP", False, "Port open; auth check not supported")

def check_mssql(ip: str, username: str, password: str):
    if not HAS_PYMSSQL:
        return ("MSSQL", False, "pymssql not installed")
    if not port_open(ip, 1433):
        return ("MSSQL", False, "TCP/1433 closed")
    try:
        conn = pymssql.connect(server=ip, user=username, password=password,
                               login_timeout=3, timeout=3)
        cur = conn.cursor()
        cur.execute("SELECT 1")
        cur.fetchall()
        conn.close()
        return ("MSSQL", True, "Authentication succeeded")
    except Exception:
        return ("MSSQL", False, "Auth failed")

# ---------- Orchestration ----------
def main():
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <IP-Range>")
        print(f"Example: {sys.argv[0]} 192.168.1.0/24")
        sys.exit(1)

    clear_screen()
    banner()
    print_imprint()

    username = input(f"{C.BOLD}Username (empty for anonymous where supported): {C.RESET}").strip()
    password = ""
    if username:
        password = getpass.getpass("Password: ")

    choice = input(f"{C.BOLD}Show only successful logins? [Y/n]: {C.RESET}").strip().lower()
    if choice == "" or choice in ("y", "yes"):
        success_only = True
    else:
        success_only = False

    network = ipaddress.ip_network(sys.argv[1], strict=False)
    hosts = [str(h) for h in network.hosts()]

    prefix = username if username else "anon"
    outfile = f"{prefix}_cred_reuse_results.txt"

    # Services to test (you can comment/uncomment as needed)
    checks = [
        ("SMB",      check_smb),
        ("SSH",      check_ssh),
        ("FTP",      check_ftp),
        ("LDAP",     check_ldap),
        ("LDAPS",    check_ldaps),
        ("LDAP-GC",  check_ldap_gc),
        ("LDAPS-GC", check_ldaps_gc),
        ("WinRM-HTTP",  check_winrm_http),
        ("WinRM-HTTPS", check_winrm_https),
        ("RDP",      check_rdp),
        ("MSSQL",    check_mssql),
    ]

    tasks = [(ip, name, fn) for ip in hosts for (name, fn) in checks]
    results = []  # (ip, service, ok, detail)

    def worker(ip, fn, name):
        s, ok, msg = fn(ip, username, password)
        # Ensure service name consistent with table headers (use s returned)
        return (ip, s, ok, msg)

    max_workers = 64
    print(f"{C.OKCYAN}")
    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        futures = [ex.submit(worker, ip, fn, name) for (ip, name, fn) in tasks]
        with tqdm(total=len(futures), desc="Testing", unit="check") as bar:
            for fut in as_completed(futures):
                ip, s, ok, msg = fut.result()
                results.append((ip, s, ok, msg))
                bar.update(1)
    print(f"{C.RESET}")
    
    # Filtering
    filtered = [r for r in results if (r[2] or not success_only)]

    # Colored output
    rows = []
    color_map = {
        "SMB": C.OKBLUE, "SSH": C.OKCYAN, "FTP": C.WARNING,
        "LDAP": C.OKBLUE, "LDAPS": C.OKBLUE, "LDAP-GC": C.OKBLUE, "LDAPS-GC": C.OKBLUE,
        "WinRM-HTTP": C.OKGREEN, "WinRM-HTTPS": C.OKGREEN,
        "RDP": C.HEADER, "MSSQL": C.OKCYAN
    }
    for ip, s, ok, msg in sorted(filtered, key=lambda x: (x[0], x[1])):
        colored_res = f"{C.OKGREEN}SUCCESS{C.RESET}" if ok else f"{C.FAIL}FAIL{C.RESET}"
        svc_color = color_map.get(s, C.WHITE)
        rows.append((
            f"{C.WHITE}{ip}{C.RESET}",
            f"{svc_color}{s}{C.RESET}",
            colored_res,
            f"{C.WHITE}{msg}{C.RESET}"
        ))

    print(f"\n{C.OKGREEN}Scan complete for {len(hosts)} hosts across Windows/AD-relevant services{C.RESET}\n")
    if rows:
        table = render_table(
            rows,
            headers=[f"{C.BOLD}IP-Address{C.RESET}", f"{C.BOLD}Service{C.RESET}",
                     f"{C.BOLD}Result{C.RESET}", f"{C.BOLD}Detail{C.RESET}"]
        )
        print(table)
    else:
        if success_only:
            print(f"{C.WARNING}No successful logins found with the provided credentials.{C.RESET}")
        else:
            print(f"{C.WARNING}No results to display.{C.RESET}")

    # Save plain table (no ANSI colors)
    plain_rows = [(ip, s, "SUCCESS" if ok else "FAIL", msg)
                  for ip, s, ok, msg in sorted(filtered, key=lambda x: (x[0], x[1]))]
    if plain_rows:
        plain_table = render_table(plain_rows, headers=["IP-Address", "Service", "Result", "Detail"])
        with open(outfile, "w") as f:
            f.write(plain_table + "\n")
        print(f"\n{C.BOLD}Results saved to: {outfile}{C.RESET}\n")
    else:
        print(f"\n{C.WARNING}Nothing to save (no rows after filtering).{C.RESET}\n")

if __name__ == "__main__":
    main()
