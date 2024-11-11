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
    "weak_credentials": "The account '{name}' has weak credentials and is a member of '{member_of}', making it a prime target for credential dumping and lateral movement.",
    "kerberos_issues": "Kerberos errors suggest time synchronization issues, which could be exploited for replay attacks and indicate potential misconfigurations in the Kerberos authentication process.",
    "weak_password_policy": "The domain password policy allows weak passwords with a minimum length of {min_length} characters and a maximum password age of {max_age}, increasing the risk of brute-force attacks.",
    "unauthorized_access_guest": "The account 'Guest' has never had a password set, indicating a potential vulnerability for unauthorized access.",
    "user_accounts_no_passwords": "Multiple accounts, such as {usernames}, have never had passwords set, indicating a risk of enumeration and unauthorized access.",
    "zerologon_vulnerability": "The system '{hostname}' was targeted for a ZeroLogon attack, but the failure indicates that it may be patched or protected against this vulnerability.",
    "smb_configuration_risks": "While SMBv1 is disabled on '{hostname}', the system remains susceptible to potential exploits due to other vulnerabilities in SMB configuration.",
    "account_enumeration": "The presence of multiple accounts with never-set passwords indicates potential user account enumeration, which attackers may exploit to gain unauthorized access.",
    "password_spraying": "The account '{name}' has a recent password that may be vulnerable to password spraying techniques if it is widely known.",
    "lateral_movement": "With several user accounts having weak or no passwords, there is an increased risk of lateral movement within the network once initial access is gained.",
    "lack_of_lockout_policy": "The absence of an account lockout threshold increases the susceptibility of user accounts to brute-force attacks.",
    "ldap_configuration_issues": "Problems with LDAP connectivity may suggest misconfigurations or vulnerabilities in the domain that could be exploited.",
    "group_policy_privileges": "Membership in 'Group Policy Creator Owners' for the '{name}' account increases the risk of unauthorized changes to Group Policy Objects, potentially affecting the entire domain.",
    "weak_admin_credentials": "The account 'Administrator' has a weak or commonly used password, making it highly vulnerable to brute-force or dictionary attacks.",
    "kerberoasting_vulnerability": "The SPN '{spn}' indicates that the '{name}' account could be vulnerable to Kerberoasting due to its recent password change."
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
        "date_created": datetime.datetime.now(datetime.timezone.utc).isoformat()  
    }
    hypotheses.append(hypothesis)
    print(f"Created Hypothesis: {hypothesis}")

# Helper function to generate a hypothesis for a keyword
def generate_hypothesis_for_keyword(hypotheses, keyword, hypothesis_text, evidence):
    if keyword in mapping:
        techniques = mapping[keyword]['techniques']
        attack_tree_focus = mapping[keyword]['attack_tree_focus']
        severity = mapping[keyword]['severity']
        create_hypothesis(hypotheses, hypothesis_text, techniques, attack_tree_focus, severity, evidence)

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
        generate_hypothesis_for_keyword(
            hypotheses,
            keyword,
            hypothesis_text,
            f"Account '{spn_info['Name']}' has weak credentials."
        )

    # Hypothesis 2 - Kerberos Authentication Issues
    if "Kerberos" in data.get("Errors", []):
        hypothesis_text = templates["kerberos_issues"]
        keyword = "kerberos issues"
        generate_hypothesis_for_keyword(
            hypotheses,
            keyword,
            hypothesis_text,
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
        generate_hypothesis_for_keyword(
            hypotheses,
            keyword,
            hypothesis_text,
            f"Password Policy: Minimum Length = {password_policy.get('Minimum_Password_Length', 0)}, "
            f"Maximum Age = {password_policy.get('Maximum_Password_Age', 0)}."
        )

    # Hypothesis 4 - Unauthorized Access via Guest Accounts
    guest_users = [user["Username"] for user in data.get("SMB_Scan", {}).get("Computers", [{}])[0].get("Users", []) if user.get("LastPWSet") == "<never>"]
    if "Guest" in guest_users:
        hypothesis_text = templates["unauthorized_access_guest"]
        keyword = "guest account"
        generate_hypothesis_for_keyword(
            hypotheses,
            keyword,
            hypothesis_text,
            "Account 'Guest' has never had a password set."
        )

    # Hypothesis 5 - User Accounts with No Passwords
    if guest_users:
        hypothesis_text = templates["user_accounts_no_passwords"].format(usernames=", ".join(guest_users))
        keyword = "user accounts no passwords"
        generate_hypothesis_for_keyword(
            hypotheses,
            keyword,
            hypothesis_text,
            "Several accounts have never had passwords set."
        )

    # Hypothesis 6 - ZeroLogon Vulnerability
    for scan in data.get("Vulnerability_Scans", []):
        if scan.get("Vulnerability") == "ZEROLOGON":
            hypothesis_text = templates["zerologon_vulnerability"].format(
                hostname=data.get("SMB_Scan", {}).get("Computers", [{}])[0].get("Hostname", "unknown")
            )
            keyword = "zerologon vulnerability"
            generate_hypothesis_for_keyword(
                hypotheses,
                keyword,
                hypothesis_text,
                "System targeted for ZeroLogon vulnerability."
            )

    # Hypothesis 7 - SMB Configuration Risks
    hypothesis_text = templates["smb_configuration_risks"].format(
        hostname=data.get("SMB_Scan", {}).get("Computers", [{}])[0].get("Hostname", "unknown")
    )
    keyword = "smb configuration risks"
    generate_hypothesis_for_keyword(
        hypotheses,
        keyword,
        hypothesis_text,
        "SMBv1 disabled, but vulnerabilities detected in scan."
    )

    # Hypothesis 8 - Account Enumeration Vulnerability
    hypothesis_text = templates["account_enumeration"]
    keyword = "account enumeration"
    generate_hypothesis_for_keyword(
        hypotheses,
        keyword,
        hypothesis_text,
        "Multiple accounts found without passwords."
    )

    # Hypothesis 9 - Password Spraying Risk
    for spn_info in data["ServicePrincipalName"]:
        hypothesis_text = templates["password_spraying"].format(name=spn_info["Name"])
        keyword = "Brute Force"
        generate_hypothesis_for_keyword(
            hypotheses,
            keyword,
            hypothesis_text,
            f"Recent password for '{spn_info['Name']}' could be vulnerable to password spraying."
        )

    # Hypothesis 10 - Lateral Movement
    hypothesis_text = templates["lateral_movement"]
    keyword = "lateral movement"
    generate_hypothesis_for_keyword(
        hypotheses,
        keyword,
        hypothesis_text,
        "Multiple accounts with weak or no passwords increase lateral movement risk."
    )

    # Hypothesis 11 - Lack of Account Lockout Policies
    hypothesis_text = templates["lack_of_lockout_policy"]
    keyword = "lockout policy"
    generate_hypothesis_for_keyword(
        hypotheses,
        keyword,
        hypothesis_text,
        "No account lockout threshold defined."
    )

    # Hypothesis 12 - LDAP Configuration Issues
    hypothesis_text = templates["ldap_configuration_issues"]
    keyword = "ldap configuration"
    generate_hypothesis_for_keyword(
        hypotheses,
        keyword,
        hypothesis_text,
        "Errors in LDAP connectivity suggest potential vulnerabilities."
    )

    # Hypothesis 13 - Risks from Group Policy Privileges
    for account in data.get("Users", []):
        if account.get("Name") == "Administrator":
            hypothesis_text = templates["group_policy_privileges"].format(name=account.get("Name"))
            keyword = "group policy privileges"
            generate_hypothesis_for_keyword(
                hypotheses,
                keyword,
                hypothesis_text,
                "Administrator account has privileges to change group policies."
            )

    # Hypothesis 14 - Kerberoasting Vulnerability
    for spn_info in data.get("ServicePrincipalName", []):
        if spn_info.get("Name"):
            hypothesis_text = templates["kerberoasting_vulnerability"].format(
                spn=spn_info.get("SPN"),
                name=spn_info.get("Name")
            )
            keyword = "kerberoasting vulnerability"
            generate_hypothesis_for_keyword(
                hypotheses,
                keyword,
                hypothesis_text,
                f"Account '{spn_info.get('Name')}' is vulnerable to Kerberoasting."
            )

    return hypotheses

# Generate hypotheses
hypotheses = generate_hypotheses(data)

# Save to file
with open('data/hypotheses_output.json', 'w') as outfile:
    json.dump(hypotheses, outfile, indent=4)

