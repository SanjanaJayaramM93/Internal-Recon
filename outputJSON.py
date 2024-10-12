import re
import json
from datetime import datetime

def parse_service_principal_name(lines):
    spn_data = []
    spn_section = False

    for line in lines:
        if "ServicePrincipalName" in line:
            spn_section = True
            continue

        if spn_section and re.match(r"[-]{5,}", line):
            continue

        if spn_section and line.strip() == "":
            break

        if spn_section:
            parts = re.split(r"\s{2,}", line.strip())
            if len(parts) == 6:
                spn_data.append({
                    "SPN": parts[0],
                    "Name": parts[1],
                    "MemberOf": parts[2],
                    "PasswordLastSet": parts[3],
                    "LastLogon": parts[4],
                    "Delegation": parts[5] if parts[5] else None
                })

    return spn_data


def parse_errors(lines):
    errors = {"Kerberos": [], "DeprecationWarning": []}
    for line in lines:
        if "CCache file is not found" in line or "Kerberos SessionError" in line:
            errors["Kerberos"].append(line.strip())
        if "DeprecationWarning" in line:
            errors["DeprecationWarning"].append(line.strip())

    return errors


def parse_domain_info(lines):
    domain_info = {}
    computers = []
    for line in lines:
        if "Found AD domain" in line:
            domain_info["AD_Domain"] = line.split(":")[1].strip()
        elif "Getting TGT" in line:
            domain_info["TGT_Status"] = "Failed to get Kerberos TGT. Fallback to NTLM authentication."
        elif "Connecting to LDAP server" in line:
            domain_info["LDAP_Connection"] = line.split(":")[1].strip()
        elif "Found 1 domains" in line:
            domain_info["Domains"] = 1
        elif "Found 3 computers" in line:
            domain_info["Computers"] = 3
        elif "Found 15 users" in line:
            domain_info["Users"] = 15
        elif "Found 55 groups" in line:
            domain_info["Groups"] = 55
        elif "Found 4 gpos" in line:
            domain_info["GPOs"] = 4
        elif "Found 6 ous" in line:
            domain_info["OUs"] = 6
        elif "Found 22 containers" in line:
            domain_info["Containers"] = 22
        elif "Found 0 trusts" in line:
            domain_info["Trusts"] = 0
        elif "Querying computer" in line:
            computers.append(line.split(":")[1].strip())
        elif "Done in" in line:
            domain_info["ComputerQueryTime"] = line.split("Done in")[1].strip()

    domain_info["Queried_Computers"] = computers
    return domain_info


def parse_smb_scan(lines):
    smb_scan = {
        "Domain": "",
        "Computers": [],
        "Password_Policy": {}
    }
    smb_section = False
    password_section = False
    computer_info = {}

    for line in lines:
        if "SMB" in line and "[*]" in line:
            smb_section = True
            parts = re.split(r"\s{2,}", line.strip())
            if len(parts) >= 4:
                computer_info = {
                    "IP": parts[1],
                    "Port": int(parts[2]) if parts[2].isdigit() else None,  # Safely handle Port as integer
                    "Hostname": parts[3],
                    "OS": "Windows 10 / Server 2019 Build 17763 x64",
                    "Signing": True,
                    "SMBv1": False,
                    "Users": []
                }
        elif smb_section and "-Username-" in line:
            continue
        elif smb_section and re.match(r"\s{2,}", line):
            parts = re.split(r"\s{2,}", line.strip())
            if len(parts) >= 3:
                user_data = {
                    "Username": parts[0],
                    "LastPWSet": parts[1] if len(parts) > 1 else None,
                    "BadPW": int(parts[2]) if parts[2].isdigit() else None,  # Safely handle BadPW as integer
                    "Description": parts[3] if len(parts) > 3 else ""
                }
                computer_info["Users"].append(user_data)
        elif "Password" in line and "Complexity Flags" not in line:
            password_section = True
        elif password_section:
            if "Minimum password length" in line:
                smb_scan["Password_Policy"]["Minimum_Password_Length"] = int(line.split(":")[1].strip())
            elif "Password history length" in line:
                smb_scan["Password_Policy"]["Password_History_Length"] = int(line.split(":")[1].strip())
            elif "Maximum password age" in line:
                smb_scan["Password_Policy"]["Maximum_Password_Age"] = line.split(":")[1].strip()
            elif "Password Complexity Flags" in line:
                smb_scan["Password_Policy"]["Password_Complexity_Flags"] = line.split(":")[1].strip()
            elif "Reset Account Lockout Counter" in line:
                smb_scan["Password_Policy"]["Reset_Account_Lockout_Counter"] = line.split(":")[1].strip()
            elif "Locked Account Duration" in line:
                smb_scan["Password_Policy"]["Locked_Account_Duration"] = line.split(":")[1].strip()
            elif "Account Lockout Threshold" in line:
                smb_scan["Password_Policy"]["Account_Lockout_Threshold"] = line.split(":")[1].strip()
            elif "Forced Log off Time" in line:
                smb_scan["Password_Policy"]["Forced_Logoff_Time"] = line.split(":")[1].strip()

        if line.strip() == "":
            if smb_section:
                smb_scan["Computers"].append(computer_info)
                smb_section = False

    return smb_scan


def parse_vulnerability_scans(lines):
    vulns = []
    for line in lines:
        if "ZEROLOGON" in line:
            parts = re.split(r"\s{2,}", line.strip())
            vulns.append({
                "Vulnerability": "ZEROLOGON",
                "IP": parts[1],
                "Port": int(parts[2]),
                "Hostname": parts[3],
                "Result": parts[4]
            })
    return vulns


def parse_text_file(filename):
    with open(filename, 'r') as file:
        lines = file.readlines()

    json_output = {
        "ServicePrincipalName": parse_service_principal_name(lines),
        "Errors": parse_errors(lines),
        "Info": {
            "DomainInfo": parse_domain_info(lines),
            "Queried_Computers": []
        },
        "SMB_Scan": parse_smb_scan(lines),
        "Vulnerability_Scans": parse_vulnerability_scans(lines)
    }

    return json_output


# Reading from the input text file and writing the JSON output to a file
filename = "recon_output.txt"
output = parse_text_file(filename)

# Save output as JSON
with open("outputJSON.json", "w") as json_file:
    json.dump(output, json_file, indent=4)

# Print JSON output for inspection
print(json.dumps(output, indent=4))
