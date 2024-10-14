import pandas as pd
import os

# Get the current working directory
current_dir = os.getcwd()

# Full file path for the input CSV
input_file_path = os.path.join(current_dir, '3.2.SecurityLog.csv')

# Load the security log CSV
try:
    df = pd.read_csv(input_file_path)
except FileNotFoundError:
    print(f"File not found at: {input_file_path}")
    exit()

# Convert the 'TimeCreated' column to datetime if needed
if 'TimeCreated' in df.columns:
    df['TimeCreated'] = pd.to_datetime(df['TimeCreated'], errors='coerce')

# Group the data by 'Id' and 'TaskDisplayName' and count the occurrences
event_counts = df.groupby(['Id', 'TaskDisplayName']).size().reset_index(name='Count')

# Sort the result by count in descending order (optional)
event_counts = event_counts.sort_values(by='Count', ascending=False)

# Display the results
print(event_counts)

# Full file path for the output CSV
output_file_path = os.path.join(current_dir, 'EventCountSummary.csv')

# Save the results to a new CSV file
event_counts.to_csv(output_file_path, index=False)

print(f"Event count summary saved to: {output_file_path}")
