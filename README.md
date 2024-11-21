# Red Team Automated Hypothesis (RAH) Tool
**Duration**: March 2024 - November 2024
## 📋 Project Overview
The Red Team Automated Hypothesis (RAH) Tool is a comprehensive solution designed for automating threat detection and hypothesis generation in an Active Directory (AD) environment. The tool integrates React.js for the frontend interface and Flask for the backend API, providing a seamless user experience for threat analysis and hypothesis management.

## Technologies

### Frontend: React.js
### Backend: Flask (Python)
### External Tools: BloodHound, CrackMapExec, Impacket, OpenVAS, MITRE ATT&CK
### Other Technologies: Python, JSON, Windows Event Logs, Threat Hunting, Active Directory Enumeration

## Project Structure
### Frontend (React)
The frontend of the RAH tool is built using React.js. It provides a user-friendly interface for interacting with the backend and visualizing the results of internal reconnaissance, hypothesis generation, and validation processes. The React app is designed to handle multiple modules, including hypothesis generation, ranking, and validation.

Here is a screenshot of the frontend interface:
![image](https://github.com/user-attachments/assets/f576fa44-b304-4620-a448-9b4d4934d6d5)


### Backend (Flask)
The backend is powered by Flask, which exposes several API endpoints that handle the logic for internal reconnaissance, hypothesis generation, and validation. The Flask API connects to external tools like BloodHound, CrackMapExec, and Impacket, as well as MITRE ATT&CK techniques for threat analysis.

### Sample Outputs
Internal Reconnaissance results
![image](https://github.com/user-attachments/assets/74e1541a-1d11-4f93-a1ba-98b70cdbd40f)
![image](https://github.com/user-attachments/assets/060798d4-0f21-45be-9061-882db2b7fdfb)

Sample Hypothesis
![image](https://github.com/user-attachments/assets/46645081-89cc-4da5-abb8-4a0397b7ea86)

Sample Hypothesis validation
![image](https://github.com/user-attachments/assets/7dd1a0fa-1044-4440-942b-e00d50e04415)

Sample Ranking
![image](https://github.com/user-attachments/assets/db26b127-b5b9-403c-86d1-c774f184111c)
 


**Details of the files In the Repository**

**1.Recon-internal module**

[1.InternalRecon.py](https://github.com/SanjanaJayaramM93/Internal-Recon/blob/main/1.InternalRecon.py) –

- Python script to perform internal reconnaissance in an active directory network.

**Required Python Packages**:

- argparse
- getpass
- subprocess

**External Tools:**

- The program relies on various external tools for Active Directory reconnaissance and exploitation:
- Impacket (GetUserSPNs.py): Required for Kerberoasting.
- .BloodHound (bloodhound-python): Required for AD enumeration.
- CrackMapExec: Required for SMB enumeration.
- nxc: Network reconnaissance tool used for various checks like LDAP signing, ZeroLogon, and noPAC.

**Access to a Domain Controller (DC):**

- The program requires valid credentials (username, password, domain, dc_ip) for interacting with the Active Directory environment.

**Command to Run**

**_python3 your_script_name.py -u &lt;username&gt; -p &lt;password&gt; -d &lt;domain&gt; -i &lt;dc_ip&gt; -s &lt;scope&gt;_**

[1.1.Internalrecon_output.txt](https://github.com/SanjanaJayaramM93/Internal-Recon/blob/main/1.1.Internalrecon_output.txt)

- Output from InternalRecon.py

[1.2.text_to_json_output.py](https://github.com/SanjanaJayaramM93/Internal-Recon/blob/main/1.2.text_to_json_output.py)\-

- Program to convert text output file to JSON

[1.3.InternalReconOutput.json](https://github.com/SanjanaJayaramM93/Internal-Recon/blob/main/1.3.InternalReconOutput.json)\-

- Internal Reconnaissance output in JSON format.

**2.Hypothesis-generation module**

[2.HypothesesGenerator.py](https://github.com/SanjanaJayaramM93/Internal-Recon/blob/main/2.HypothesesGenerator.py) –

- Python program to generate hypotheses based on internal reconnaissance.
- 2 inputs.: [1.3.InternalReconOutput.json](https://github.com/SanjanaJayaramM93/Internal-Recon/blob/main/1.3.InternalReconOutput.json), [2.1.MITREattack.json](https://github.com/SanjanaJayaramM93/Internal-Recon/blob/main/2.1.MITREattack.json)

[2.1.MITREattack.json](https://github.com/SanjanaJayaramM93/Internal-Recon/blob/main/2.1.MITREattack.json) –

list of attack techniques from the MITRE ATT&CK framework. Each entry includes the following details:

- **MITRE Technique**: The specific attack technique identifier (e.g., "T1003").
- **Attack Tree Focus**: A description of the focus of the attack or security risk (e.g., "Credential Dumping").
- **Keywords**: A list of relevant terms associated with the technique (e.g., "password", "hash").
- **Severity**: The severity level of the technique, categorized as "High" or "Medium".

[2.2.hypotheses_output.json](https://github.com/SanjanaJayaramM93/Internal-Recon/blob/main/2.2.hypotheses_output.json) –

- Output file of [2.HypothesesGenerator.py](https://github.com/SanjanaJayaramM93/Internal-Recon/blob/main/2.HypothesesGenerator.py).

Each entry consists of-

- **ID**: A unique identifier for the hypothesis (e.g., "hypothesis-1").
- **Hypothesis**
- **MITRE Techniques**
- **Attack Tree Focus**
- **Severity**:
- **Evidence**: Supporting information that backs the hypothesis.
- **Date Created**: The timestamp of when the hypothesis was created.

**3.Module for hypothesis validation**

[3.validation.py](https://github.com/SanjanaJayaramM93/Internal-Recon/blob/main/3.validation.py)

- Python program to validate security hypotheses ([2.2.hypotheses_output.json](https://github.com/SanjanaJayaramM93/Internal-Recon/blob/main/2.2.hypotheses_output.json)) using log data.

1. **Load Hypotheses**: Reads [2.2.hypotheses_output.json](https://github.com/SanjanaJayaramM93/Internal-Recon/blob/main/2.2.hypotheses_output.json).
2. **Load MITRE Event IDs**: Loads [3.1.MITREattack_eventid.json](https://github.com/SanjanaJayaramM93/Internal-Recon/blob/main/3.1.MITREattack_eventid.json).
3. **Load Log Summary**: Reads [3.4.logSummary.csv](https://github.com/SanjanaJayaramM93/Internal-Recon/blob/main/3.4.logSummary.csv) file with counts of logged event IDs.
4. **Validate Hypotheses**: For each hypothesis, check if the associated MITRE techniques are present in the log data and record event ID validation results, including event count and criticality.
5. **Save Updated Hypotheses**: [3.5.updated_hypotheses.json](https://github.com/SanjanaJayaramM93/Internal-Recon/blob/main/3.5.updated_hypotheses.json).

[3.1.MITREattack_eventid.json](https://github.com/SanjanaJayaramM93/Internal-Recon/blob/main/3.1.MITREattack_eventid.json)

- Mapping of MITRE attack techniques to associated Windows Event IDs.

[3.2.SecurityLog.csv](https://github.com/SanjanaJayaramM93/Internal-Recon/blob/main/3.2.SecurityLog.csv)– Events collected from Windows server.

[3.3.EventIdCount.py](https://github.com/SanjanaJayaramM93/Internal-Recon/blob/main/3.3.EventIdCount.py) -Python program to find unique events in the security log and their count.

[3.4.logSummary.csv](https://github.com/SanjanaJayaramM93/Internal-Recon/blob/main/3.4.logSummary.csv)\- file with counts of logged event IDs.

[3.5.updated_hypotheses.json](https://github.com/SanjanaJayaramM93/Internal-Recon/blob/main/3.5.updated_hypotheses.json).– validated hypotheses with the new log-based evidence.

**Hypothesis-rank module**

[4.Ranking.py](https://github.com/SanjanaJayaramM93/Internal-Recon/blob/main/4.Ranking.py"%20\o%20"4.Ranking.py) - calculates and ranks hypotheses based on various weighted parameters such as the **severity of MITRE techniques, the criticality of event IDs, event counts, the number of unique events, and the nature of evidence**.

- Load hypotheses from: [3.5.updated_hypotheses.json](https://github.com/SanjanaJayaramM93/Internal-Recon/blob/main/3.5.updated_hypotheses.json)
- It contains :
- **Weight Definitions**: Defines weights for parameters like severity, criticality, event count, unique events, and evidence type.
- **Scoring Calculation**: For each hypothesis, calculate a total score by multiplying the corresponding values with their defined weights. The program also scores event ID counts, the number of unique events, and the nature of evidence.
- **Ranking Hypotheses**: After scoring, the hypotheses are sorted by their score, and ranks are assigned. In the case of tied scores, severity and criticality are used as tiebreakers.

[4.1.updated_hypotheses_with_scores_and_ranks.json](https://github.com/SanjanaJayaramM93/Internal-Recon/blob/main/4.1.updated_hypotheses_with_scores_and_ranks.json) – final hypotheses file with evidence,validation and ranking details.

**Represent-state module & Attack-tree module**

[BloodHound_Enumeration](https://github.com/SanjanaJayaramM93/Internal-Recon/tree/main/BloodHound_Enumeration)\- JSON files from Bloodhound

[BloodHound_AttackTree](https://github.com/SanjanaJayaramM93/Internal-Recon/tree/main/BloodHound_AttackTree)\- Files containing images and JSON files from bloodhound analysis.
## Installation & Setup
Clone the repository:

```bash
git clone https://github.com/SanjanaJayaramM93/Internal-Recon.git

### Install the required Python packages:

```bash
pip install -r requirements.txt
### Ensure external tools (Impacket, BloodHound, CrackMapExec) are installed on your machine.

### For the React frontend:

Navigate to the frontend directory.
Install the necessary npm packages:
```bash
npm install
### Start the React development server:
```bash
npm start

## Usage
Run InternalRecon.py to start internal reconnaissance.
Use HypothesesGenerator.py to generate hypotheses based on the reconnaissance data.
Validate the hypotheses with validation.py, using Windows Event Logs.
Rank the hypotheses with Ranking.py to prioritize security risks.
Access the frontend to view the results and interact with the tool.

## Contributing
Feel free to fork the repository and submit pull requests. Contributions to enhance the tool's functionality or fix bugs are welcome.
