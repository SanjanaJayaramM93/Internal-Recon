import os
import io
import json
import csv
import subprocess  
from flask import Flask, render_template, request, jsonify
from modules.HypothesesGenerator import generate_hypotheses
from modules.Ranking import rank_hypotheses_function

app = Flask(__name__)

# Home page route
@app.route('/')
def home():
    return render_template('index.html')

# Submit route for the internal reconnaissance tool
@app.route('/internal-recon', methods=['POST'])
def submit():
    username = request.form['username']
    password = request.form['password']
    domain = request.form['domain']
    ip = request.form['ip']
    scope = request.form['scope']

    # Call the internal reconnaissance script with its updated path
    output_file_path = 'Internalrecon_output.txt'  # Ensure this matches the output file of InternalRecon.py
    try:
        subprocess.run(
            ["python3", "modules/InternalRecon.py", "-u", username, "-p", password, "-d", domain, "-i", ip, "-s", scope],
            check=True  # Raises CalledProcessError if the command fails
        )
    except subprocess.CalledProcessError as e:
        return render_template('output.html', output=[f"Error running script: {str(e)}"])

    # Read the output file(s)
    output = []
    if os.path.exists(output_file_path):
        with open(output_file_path, 'r') as file:
            output = file.readlines()
    else:
        output = ["Error: Output file not found. Please check if the reconnaissance script ran correctly."]

    # Render a new template to display the output
    return render_template('output.html', output=output)

# Route for the Attack Tree Generator
@app.route('/attack-tree')
def attack_tree():
    return render_template('attack_tree.html')

# Route for the Hypotheses Generator
@app.route('/generate_hypotheses', methods=['POST'])
def generate_hypotheses():
    try:
        # Run the HypothesisGenerator.py script
        subprocess.run(['python', 'modules/HypothesesGenerator.py'], check=True)

        # Load the generated hypotheses from the output file
        with open('data/hypotheses_output.json', 'r') as json_file:
            hypotheses = json.load(json_file)

        return render_template('hypotheses_output.html', hypotheses=hypotheses)

    except (FileNotFoundError, json.JSONDecodeError, subprocess.CalledProcessError) as e:
        return jsonify({"error": "Error generating hypotheses: " + str(e)}), 500

# Route for hypothesis validation
# Load the hypothesis data from a JSON file
def load_hypotheses(file_path):
    with open(file_path, 'r') as file:
        return json.load(file)

# Load the MITRE attack techniques and associated event IDs
def load_mitre_event_ids(file_path):
    with open(file_path, 'r') as file:
        return json.load(file)

# Load the log summary CSV and return a dictionary with event ID counts
def load_log_summary(file):
    log_counts = {}
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

# Save the updated hypotheses to a file
def save_updated_hypotheses(hypotheses, output_file):
    with open(output_file, 'w') as file:
        json.dump(hypotheses, file, indent=4)

@app.route('/validate_hypotheses', methods=['POST'])
def validate_hypotheses_route():
    try:
        # Save uploaded log file
        uploaded_file = request.files['logfile']
        if uploaded_file.filename != '':
            # Convert the uploaded file from binary to text mode
            log_file = io.TextIOWrapper(uploaded_file, encoding='utf-8')

            # Use the uploaded file
            log_counts = load_log_summary(log_file)

            # Load hypothesis and MITRE event ID data from JSON files
            hypotheses = load_hypotheses('data/hypotheses_output.json')
            mitre_event_ids = load_mitre_event_ids('data/MITREattack_eventid.json')

            # Validate the hypotheses
            updated_hypotheses = validate_hypotheses(hypotheses, mitre_event_ids, log_counts)

            # Save the updated hypotheses to the data folder
            save_updated_hypotheses(updated_hypotheses, 'data/validated_hypotheses.json')

            # Display the results on the webpage
            return render_template('index.html', updated_hypotheses=updated_hypotheses)
        else:
            return jsonify({"error": "No file uploaded"}), 400
    except Exception as e:
        return jsonify({"error": str(e)}), 500
@app.route('/')
def index():
    return render_template('index.html')




@app.route('/rank', methods=['POST'])
def rank_hypotheses():
    try:
        # Call the function to rank hypotheses
        ranked_hypotheses = rank_hypotheses_function()  # Now this function should be recognized

        # Load the ranked hypotheses JSON file to pass to the frontend
        with open("data/ranked_hypotheses.json", "r") as f:
            ranked_hypotheses = json.load(f)

        # Send ranked hypotheses to the frontend
        return render_template('ranked_hypotheses.html', hypotheses=ranked_hypotheses)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)









