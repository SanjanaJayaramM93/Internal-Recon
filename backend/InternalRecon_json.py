import json
import re

# Function to parse the log data and structure it into a JSON-compatible format
def parse_log_data(log_data):
    structured_data = {
        "info": [],
        "warning": [],
        "error": [],
        "smb": [],
        "attack_results": []
    }

    # Split the log into lines for processing
    lines = log_data.split('\n')

    # Loop through each line and categorize it based on the log type
    for line in lines:
        if line.startswith('INFO:'):
            structured_data["info"].append(line[5:].strip())
        elif line.startswith('WARNING:'):
            structured_data["warning"].append(line[8:].strip())
        elif line.startswith('ERROR:'):
            structured_data["error"].append(line[6:].strip())
        elif line.startswith('SMB'):
            smb_match = re.match(r"SMB\s+(\S+)\s+(\d+)\s+(\S+)\s+\[\*\]\s+([^\[]+)", line)
            if smb_match:
                smb_data = {
                    "ip": smb_match.group(1),
                    "port": smb_match.group(2),
                    "hostname": smb_match.group(3),
                    "details": smb_match.group(4)
                }
                structured_data["smb"].append(smb_data)
        elif line.startswith('ZEROLOGON') or line.startswith('NOPAC'):
            attack_data = {
                "attack_type": line.split()[0],
                "ip": line.split()[1],
                "port": line.split()[2],
                "hostname": line.split()[3],
                "result": " ".join(line.split()[4:])
            }
            structured_data["attack_results"].append(attack_data)

    return structured_data

# Read the log data from the input file
input_file_path = 'Internalrecon_output.txt'  # Input file with log data
with open(input_file_path, 'r') as file:
    log_data = file.read()

# Parse the log data
parsed_data = parse_log_data(log_data)

# Write the structured data to a JSON file
output_file_path = 'InternalRecon.json'  # Output file for the structured JSON data
with open(output_file_path, 'w') as json_file:
    json.dump(parsed_data, json_file, indent=4)

print(f"Log data has been structured and saved to {output_file_path}")
