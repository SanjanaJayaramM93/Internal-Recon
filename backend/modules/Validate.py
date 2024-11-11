import json
import csv

# Load the hypothesis data from a JSON file
def load_hypotheses(file_path):
    with open(file_path, 'r') as file:
        return json.load(file)

# Load the MITRE attack techniques and associated event IDs
def load_mitre_event_ids(file_path):
    with open(file_path, 'r') as file:
        return json.load(file)

# Load the log summary CSV and return a dictionary with event ID counts
def load_log_summary(file_path):
    log_counts = {}
    with open(file_path, 'r') as file:
        reader = csv.DictReader(file)
        for row in reader:
            log_counts[row['Id']] = int(row['Count'])
    return log_counts

# Validate hypotheses based on log counts
def validate_hypotheses(hypotheses, mitre_event_ids, log_counts):
    for hypothesis in hypotheses:
        hypothesis['validation'] = {}
        for technique in hypothesis['mitre_techniques']:
            if technique in mitre_event_ids:
                for event in mitre_event_ids[technique]:
                    event_id = event['event_id']
                    if event_id in log_counts:
                        # Record validation results
                        hypothesis['validation'][event_id] = {
                            "description": event['description'],
                            "count": log_counts[event_id],
                            "criticality": event['criticality']
                        }
    return hypotheses

# Save the updated hypotheses to a JSON file
def save_updated_hypotheses(hypotheses, output_file):
    with open(output_file, 'w') as file:
        json.dump(hypotheses, file, indent=4)

def main():
    hypothesis_file = 'data/hypotheses_output.json'  # Path to the hypothesis file
    mitre_event_id_file = 'data/MITREattack_eventid.json'  # Path to the MITRE event ID file
    log_summary_file = 'logSummary.csv'  # Path to the log summary CSV
    output_file = 'updated_hypotheses.json'  # Path to save the updated hypotheses

    # Load data
    hypotheses = load_hypotheses(hypothesis_file)
    mitre_event_ids = load_mitre_event_ids(mitre_event_id_file)
    log_counts = load_log_summary(log_summary_file)

    # Validate hypotheses
    updated_hypotheses = validate_hypotheses(hypotheses, mitre_event_ids, log_counts)

    # Save updated hypotheses
    save_updated_hypotheses(updated_hypotheses, output_file)

if __name__ == '__main__':
    main()