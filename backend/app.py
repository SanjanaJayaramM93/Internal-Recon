import os
import json
import subprocess
import time
from flask import Flask, request, jsonify, send_file, send_from_directory
from flask_cors import CORS
from modules.HypothesesGenerator import generate_hypotheses
from modules.Ranking import rank_hypotheses_function

app = Flask(__name__)

# Enable CORS for specific domains (replace with your frontend URL)
CORS(app, resources={r"/*": {"origins": "http://localhost:3000"}})

# Set the path for images and other static files
app.config['IMAGE_FOLDER'] = os.path.join(os.path.abspath(os.path.dirname(__file__)), 'static')  # Absolute path

# Home page route (optional)
@app.route('/')
def home():
    return jsonify({"message": "Welcome to the Internal Recon Tool API"})

@app.route('/internal-recon', methods=['POST'])
def submit():
    # Extract JSON data from the request
    username = request.json.get('username')
    password = request.json.get('password')
    domain = request.json.get('domain')
    ip = request.json.get('ip')
    scope = request.json.get('scope')

    # Define the output file path for the text output
    output_file_path = 'Internalrecon_output.txt'

    # Check if all parameters are provided
    if not all([username, password, domain, ip, scope]):
        return jsonify({"error": "Missing required parameters."}), 400

    # Define the absolute path to the InternalRecon.py file
    internal_recon_script = os.path.join(os.path.abspath(os.path.dirname(__file__)), 'modules', 'InternalRecon.py')

    # Try running the reconnaissance script with subprocess
    try:
        subprocess.run(
            ["python3", internal_recon_script, "-u", username, "-p", password, "-d", domain, "-i", ip, "-s", scope],
            check=True
        )
    except subprocess.CalledProcessError as e:
        return jsonify({"error": f"Error running script: {str(e)}"}), 500

    # Wait for the output file to be generated and populated
    if not wait_for_file(output_file_path):
        return jsonify({"error": "Reconnaissance output file was not created or is empty."}), 500

    # Convert the output into JSON for the frontend
    try:
        subprocess.run(['python3', 'InternalRecon_json.py'], check=True)
        
        # Define the relative path to the generated JSON file
        json_file_path = os.path.join(os.path.dirname(__file__), 'modules', 'InternalRecon.json')

        # Check if the JSON file exists
        if os.path.exists(json_file_path):
            with open(json_file_path, 'r') as json_file:
                json_output = json.load(json_file)
            return jsonify({"output": json_output})
        else:
            return jsonify({"error": "Generated JSON file not found."}), 500

    except subprocess.CalledProcessError as e:
        return jsonify({"error": f"Error during the conversion process: {e}"}), 500

# Path to the hypotheses output JSON file
OUTPUT_FILE_PATH = 'data/hypotheses_output.json'

@app.route('/get-hypotheses', methods=['GET'])
def get_hypotheses():
    try:
        print(f"Checking if hypotheses file exists at {OUTPUT_FILE_PATH}...")
        # Make sure the file exists before trying to read it
        if not os.path.exists(OUTPUT_FILE_PATH):
            return jsonify({"error": "Hypotheses file not found"}), 404
        
        # Read the hypotheses output file
        with open(OUTPUT_FILE_PATH, 'r') as file:
            hypotheses = json.load(file)

        # Return the JSON data as a response
        return jsonify(hypotheses)
    
    except Exception as e:
        # If an error occurs, return a 500 status code with the error message
        print(f"Error while reading hypotheses file: {str(e)}")
        return jsonify({"error": str(e)}), 500

@app.route('/validate_hypotheses', methods=['GET', 'POST'])
def get_validated_hypotheses():
    file_path = os.path.join('data', 'validated_hypotheses.json')
    if request.method == 'POST':
        return send_file(file_path, mimetype='application/json')
    elif request.method == 'GET':
        return send_file(file_path, mimetype='application/json')


# Route for hypothesis ranking
@app.route('/rank', methods=['POST'])
def rank_hypotheses():
    try:
        ranked_hypotheses = rank_hypotheses_function()
        with open("data/ranked_hypotheses.json", "r") as f:
            ranked_hypotheses = json.load(f)
        return jsonify({"ranked_hypotheses": ranked_hypotheses})

    except Exception as e:
        return jsonify({"error": str(e)}), 500

# Route to list the images
@app.route('/images', methods=['GET'])
def list_images():
    image_files = [
        'DomainAdmins.png',
        'Shortest_Paths_to_Domain_Admin.png',
        'Shortest_Paths_to_High_Value_Targets.png',
        'Shortest_Paths_to_Unconstrained_Delegation_Systems.png'
    ]
    return jsonify(image_files)

# Route to serve individual images
@app.route('/images/<filename>', methods=['GET'])
def get_image(filename):
    try:
        return send_from_directory(app.config['IMAGE_FOLDER'], filename)
    except FileNotFoundError:
        return jsonify({"error": "Image not found"}), 404

# Helper functions for validation
def load_hypotheses(file_path):
    with open(file_path, 'r') as file:
        return json.load(file)

def load_mitre_event_ids(file_path):
    with open(file_path, 'r') as file:
        return json.load(file)

def load_log_summary(file):
    log_counts = {}
    reader = csv.DictReader(file)
    for row in reader:
        log_counts[row['Id']] = int(row['Count'])
    return log_counts

def validate_hypotheses(hypotheses, mitre_event_ids, log_counts):
    for hypothesis in hypotheses:
        hypothesis['validation'] = {}
        for technique in hypothesis['mitre_techniques']:
            if technique in mitre_event_ids:
                for event in mitre_event_ids[technique]:
                    event_id = event['event_id']
                    if event_id in log_counts:
                        hypothesis['validation'][event_id] = {
                            "description": event['description'],
                            "count": log_counts[event_id],
                            "criticality": event['criticality']
                        }
    return hypotheses

def save_updated_hypotheses(hypotheses, output_file):
    with open(output_file, 'w') as file:
        json.dump(hypotheses, file, indent=4)

# Request logging (optional, helpful for debugging)
@app.before_request
def log_request_info():
    print(f"Request Method: {request.method} | Request Path: {request.path}")

# Wait until the file is created and populated
def wait_for_file(file_path, timeout=60, check_interval=1):
    """
    Wait until the file is created and contains data.
    :param file_path: Path to the file to wait for.
    :param timeout: Maximum time (in seconds) to wait.
    :param check_interval: Time (in seconds) between checks.
    :return: True if the file exists and is not empty, False otherwise.
    """
    start_time = time.time()
    
    while True:
        if os.path.exists(file_path) and os.path.getsize(file_path) > 0:
            print(f"{file_path} has been created and contains data.")
            return True
        elif time.time() - start_time > timeout:
            print(f"Timeout reached. {file_path} was not created or is empty.")
            return False
        
        time.sleep(check_interval)  # Wait before checking again
@app.route('/api/ranked_hypotheses', methods=['GET'])
def get_ranked_hypotheses():
    try:
        with open("data/ranked_hypotheses.json", "r") as file:
            ranked_hypotheses = json.load(file)
        return jsonify(ranked_hypotheses)
    except Exception as e:
        print(f"Error fetching ranked hypotheses: {str(e)}")
        return jsonify({"error": f"Error fetching ranked hypotheses: {str(e)}"}), 500


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5001)



