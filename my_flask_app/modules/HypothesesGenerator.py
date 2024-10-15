import json
import datetime

# Load JSON data
with open('data/InternalReconOutput.json', 'r') as json_file:
    data = json.load(json_file)

# Load MITRE techniques mapping from JSON
mapping = {}
with open('data/MITREattack.json', 'r') as jsonfile:
    techniques_data = json.load(jsonfile)
    for row in techniques_data:
        for keyword in row['Keywords']:
            mapping[keyword] = {
                'techniques': [row['MITRE Technique']],  # Store technique as a list
                'attack_tree_focus': row['Attack Tree Focus'],
                'severity': row['Severity']
            }

# Define hypothesis templates
templates = {
    "weak_credentials": "The account '{name}' has weak credentials and is a member of '{member_of}', making it a prime target for credential dumping.",
    "kerberos_issues": "Kerberos errors suggest time synchronization issues, which could be exploited for replay attacks.",
    "weak_password_policy": "The domain password policy allows weak passwords with a minimum length of {min_length} characters.",
    "unauthorized_access_guest": "The account 'Guest' has never had a password set, indicating a potential vulnerability.",
    "user_accounts_no_passwords": "Multiple accounts, such as {usernames}, have never had passwords set, indicating a risk.",
    "zerologon_vulnerability": "The system '{hostname}' was targeted for a ZeroLogon attack, but the failure indicates it may be protected.",
    "smb_configuration_risks": "While SMBv1 is disabled on '{hostname}', vulnerabilities may still exist.",
    "account_enumeration": "Multiple accounts with never-set passwords indicate potential enumeration.",
    "password_spraying": "The account '{name}' may be vulnerable to password spraying techniques.",
    "lateral_movement": "With several user accounts having weak or no passwords, there's an increased risk of lateral movement.",
    "lack_of_lockout_policy": "The absence of an account lockout threshold increases susceptibility to brute-force attacks.",
    "ldap_configuration_issues": "Problems with LDAP connectivity may suggest misconfigurations.",
    "group_policy_privileges": "Membership in 'Group Policy Creator Owners' for the '{name}' account increases risk.",
    "weak_admin_credentials": "The account 'Administrator' has a weak or commonly used password.",
    "kerberoasting_vulnerability": "The SPN '{spn}' indicates that the '{name}' account could be vulnerable to Kerberoasting."
}

# Hypothesis creation function
def create_hypothesis(hypotheses, hypothesis_text, techniques, attack_tree_focus, severity, evidence):
    hypothesis = {
        "id": f'hypothesis-{len(hypotheses) + 1}',
        'hypothesis': hypothesis_text,
        'mitre_techniques': techniques,
        'attack_tree_focus': attack_tree_focus,
        'severity': severity,
        'evidence': evidence,
        "date_created": datetime.datetime.now(datetime.timezone.utc).isoformat()  # Use timezone-aware datetime
    }
    hypotheses.append(hypothesis)
    #print(f"Created Hypothesis: {hypothesis}")

# Generate hypotheses based on conditions in the data
def generate_hypotheses(data):
    hypotheses = []

    # Hypothesis 1 - Weak Credentials for Service Accounts
    for spn_info in data.get("ServicePrincipalName", []):
        hypothesis_text = templates["weak_credentials"].format(
            name=spn_info["Name"],
            member_of=spn_info["MemberOf"]
        )
        keyword = "weak credentials"
        if keyword in mapping:
            create_hypothesis(
                hypotheses,
                hypothesis_text,
                mapping[keyword]['techniques'],
                mapping[keyword]['attack_tree_focus'],
                mapping[keyword]['severity'],
                f"Account '{spn_info['Name']}' has weak credentials."
            )

    # Hypothesis 2 - Kerberos Authentication Issues
    if "Kerberos" in data.get("Errors", []):
        hypothesis_text = templates["kerberos_issues"]
        keyword = "kerberos issues"
        if keyword in mapping:
            create_hypothesis(
                hypotheses,
                hypothesis_text,
                mapping[keyword]['techniques'],
                mapping[keyword]['attack_tree_focus'],
                mapping[keyword]['severity'],
                "Kerberos error indicates time skew."
            )

    # Hypothesis 3 - Weak Password Policy
    password_policy = data.get("SMB_Scan", {}).get("Password_Policy", {})
    if password_policy:
        hypothesis_text = templates["weak_password_policy"].format(
            min_length=password_policy.get("Minimum_Password_Length", 0),
            max_age=password_policy.get("Maximum_Password_Age", 0)
        )
        keyword = "weak password policy"
        if keyword in mapping:
            create_hypothesis(
                hypotheses,
                hypothesis_text,
                mapping[keyword]['techniques'],
                mapping[keyword]['attack_tree_focus'],
                mapping[keyword]['severity'],
                f"Password Policy: Min Length = {password_policy.get('Minimum_Password_Length', 0)}, Max Age = {password_policy.get('Maximum_Password_Age', 0)}."
            )

    # Hypothesis 4 - Unauthorized Access via Guest Accounts
    guest_users = [user["Username"] for user in data.get("SMB_Scan", {}).get("Computers", [{}])[0].get("Users", []) if user.get("LastPWSet") == "<never>"]
    if "Guest" in guest_users:
        hypothesis_text = templates["unauthorized_access_guest"]
        keyword = "guest account"
        if keyword in mapping:
            create_hypothesis(
                hypotheses,
                hypothesis_text,
                mapping[keyword]['techniques'],
                mapping[keyword]['attack_tree_focus'],
                mapping[keyword]['severity'],
                "Account 'Guest' has never had a password set."
            )

    # Hypothesis 5 - User Accounts with No Passwords
    if guest_users:
        hypothesis_text = templates["user_accounts_no_passwords"].format(usernames=", ".join(guest_users))
        keyword = "user accounts no passwords"
        if keyword in mapping:
            create_hypothesis(
                hypotheses,
                hypothesis_text,
                mapping[keyword]['techniques'],
                mapping[keyword]['attack_tree_focus'],
                mapping[keyword]['severity'],
                "Several accounts have never had passwords set."
            )

    # Hypothesis 6 - ZeroLogon Vulnerability
    for scan in data.get("Vulnerability_Scans", []):
        if scan.get("Vulnerability") == "ZEROLOGON":
            hypothesis_text = templates["zerologon_vulnerability"].format(
                hostname=data.get("SMB_Scan", {}).get("Computers", [{}])[0].get("Hostname", "unknown")
            )
            keyword = "zerologon vulnerability"
            if keyword in mapping:
                create_hypothesis(
                    hypotheses,
                    hypothesis_text,
                    mapping[keyword]['techniques'],
                    mapping[keyword]['attack_tree_focus'],
                    mapping[keyword]['severity'],
                    "System targeted for ZeroLogon vulnerability."
                )

    # Hypothesis 7 - SMB Configuration Risks
    hypothesis_text = templates["smb_configuration_risks"].format(
        hostname=data.get("SMB_Scan", {}).get("Computers", [{}])[0].get("Hostname", "unknown")
    )
    keyword = "smb configuration risks"
    if keyword in mapping:
        create_hypothesis(
            hypotheses,
            hypothesis_text,
            mapping[keyword]['techniques'],
            mapping[keyword]['attack_tree_focus'],
            mapping[keyword]['severity'],
            "SMBv1 disabled, but vulnerabilities detected in scan."
        )

    # Hypothesis 8 - Account Enumeration Vulnerability
    hypothesis_text = templates["account_enumeration"]
    keyword = "account enumeration"
    if keyword in mapping:
        create_hypothesis(
            hypotheses,
            hypothesis_text,
            mapping[keyword]['techniques'],
            mapping[keyword]['attack_tree_focus'],
            mapping[keyword]['severity'],
            "Multiple accounts found without passwords."
        )

    # Hypothesis 9 - Password Spraying Risk
    for spn_info in data["ServicePrincipalName"]:
        hypothesis_text = templates["password_spraying"].format(name=spn_info["Name"])
        keyword = "Brute Force"
        if keyword in mapping:
            create_hypothesis(
                hypotheses,
                hypothesis_text,
                mapping[keyword]['techniques'],
                mapping[keyword]['attack_tree_focus'],
                mapping[keyword]['severity'],
                "Recent password for '{}' could be vulnerable to password spraying.".format(spn_info["Name"])
            )

    # Hypothesis 10 - Lateral Movement
    hypothesis_text = templates["lateral_movement"]
    keyword = "lateral movement"
    if keyword in mapping:
        create_hypothesis(
            hypotheses,
            hypothesis_text,
            mapping[keyword]['techniques'],
            mapping[keyword]['attack_tree_focus'],
            mapping[keyword]['severity'],
            "Multiple accounts with weak or no passwords increase lateral movement risk."
        )

    # Hypothesis 11 - Lack of Account Lockout Policies
    hypothesis_text = templates["lack_of_lockout_policy"]
    keyword = "lockout policy"
    if keyword in mapping:
        create_hypothesis(
            hypotheses,
            hypothesis_text,
            mapping[keyword]['techniques'],
            mapping[keyword]['attack_tree_focus'],
            mapping[keyword]['severity'],
            "No account lockout threshold defined."
        )

    # Hypothesis 12 - LDAP Configuration Issues
    hypothesis_text = templates["ldap_configuration_issues"]
    keyword = "ldap configuration"
    if keyword in mapping:
        create_hypothesis(
            hypotheses,
            hypothesis_text,
            mapping[keyword]['techniques'],
            mapping[keyword]['attack_tree_focus'],
            mapping[keyword]['severity'],
            "Potential LDAP connectivity issues detected."
        )

    # Hypothesis 13 - Group Policy Privileges
    for user in data.get("Group_Policy", []):
        if user.get("Privileged") == "True":
            hypothesis_text = templates["group_policy_privileges"].format(name=user["Name"])
            keyword = "group policy privileges"
            if keyword in mapping:
                create_hypothesis(
                    hypotheses,
                    hypothesis_text,
                    mapping[keyword]['techniques'],
                    mapping[keyword]['attack_tree_focus'],
                    mapping[keyword]['severity'],
                    f"{user['Name']} is a member of Group Policy Creator Owners."
                )

    # Hypothesis 14 - Weak Admin Credentials
    admin_account = data.get("Admin_Accounts", {}).get("AdminAccount", "Administrator")
    hypothesis_text = templates["weak_admin_credentials"]
    keyword = "weak admin credentials"
    if keyword in mapping:
        create_hypothesis(
            hypotheses,
            hypothesis_text,
            mapping[keyword]['techniques'],
            mapping[keyword]['attack_tree_focus'],
            mapping[keyword]['severity'],
            f"The account '{admin_account}' has a weak password."
        )

    # Hypothesis 15 - Kerberoasting Vulnerability
    for spn_info in data.get("ServicePrincipalName", []):
        if "Kerberoasting" in spn_info.get("Services", []):
            hypothesis_text = templates["kerberoasting_vulnerability"].format(
                spn=spn_info.get("ServicePrincipalName"),
                name=spn_info["Name"]
            )
            keyword = "kerberoasting vulnerability"
            if keyword in mapping:
                create_hypothesis(
                    hypotheses,
                    hypothesis_text,
                    mapping[keyword]['techniques'],
                    mapping[keyword]['attack_tree_focus'],
                    mapping[keyword]['severity'],
                    f"SPN '{spn_info.get('ServicePrincipalName')}' indicates potential for Kerberoasting."
                )

    return hypotheses

# Generate hypotheses and output results
generated_hypotheses = generate_hypotheses(data)

# Output to a new JSON file
output_filename = 'data/hypotheses_output.json'
with open(output_filename, 'w') as output_file:
    json.dump(generated_hypotheses, output_file, indent=4)

#print(f"{len(generated_hypotheses)} hypotheses generated and saved to '{output_filename}'.")
