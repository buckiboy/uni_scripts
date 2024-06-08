import pandas as pd
import re
from datetime import datetime

def parse_snort_log(log_file):
    # Regular expression patterns for parsing Snort logs
    alert_pattern = re.compile(r'\[\*\*\] \[(\d+):(\d+):(\d+)\] "(.+?)" \[\*\*\]')
    classification_pattern = re.compile(r'\[Classification: (.+?)\]')
    date_ip_pattern = re.compile(r'(\d+/\d+)-(\d+:\d+:\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+):(\d+) -> (\d+\.\d+\.\d+\.\d+):(\d+)')
    protocol_pattern = re.compile(r'(TCP|UDP|ICMP)')

    parsed_data = []
    current_entry = {}

    with open(log_file, 'r') as file:
        lines = file.readlines()

        for line in lines:
            alert_match = alert_pattern.search(line)
            classification_match = classification_pattern.search(line)
            date_ip_match = date_ip_pattern.search(line)
            protocol_match = protocol_pattern.search(line)

            if alert_match:
                if current_entry:
                    # Save the previous entry if it's complete
                    if 'date' in current_entry and 'time' in current_entry and 'src_ip' in current_entry:
                        timestamp = datetime.strptime(f"2024/{current_entry['date']} {current_entry['time']}", '%Y/%m/%d %H:%M:%S.%f')
                        current_entry['timestamp'] = timestamp.strftime('%Y-%m-%d %H:%M:%S')
                        parsed_data.append(current_entry)
                # Start a new entry
                current_entry = {
                    'signature': alert_match.group(4),
                }

            if classification_match:
                current_entry['classification'] = classification_match.group(1)

            if date_ip_match:
                current_entry['date'] = date_ip_match.group(1)
                current_entry['time'] = date_ip_match.group(2)
                current_entry['src_ip'] = date_ip_match.group(3)
                current_entry['src_port'] = date_ip_match.group(4)
                current_entry['dst_ip'] = date_ip_match.group(5)
                current_entry['dst_port'] = date_ip_match.group(6)

            if protocol_match:
                current_entry['protocol'] = protocol_match.group(1)

        # Append the last entry if it's complete
        if current_entry and 'date' in current_entry and 'time' in current_entry and 'src_ip' in current_entry:
            timestamp = datetime.strptime(f"2024/{current_entry['date']} {current_entry['time']}", '%Y/%m/%d %H:%M:%S.%f')
            current_entry['timestamp'] = timestamp.strftime('%Y-%m-%d %H:%M:%S')
            parsed_data.append(current_entry)

    return pd.DataFrame(parsed_data)

def preprocess_and_save_to_csv(df, output_file):
    # Drop unwanted columns
    df = df.drop(columns=['date', 'time', 'classification'])

    # Reorder columns to place timestamp first
    columns = ['timestamp', 'protocol', 'src_ip', 'src_port', 'dst_ip', 'dst_port', 'signature']
    df = df[columns]

    # Deduplicate the DataFrame
    df = df.drop_duplicates()

    # Print the DataFrame for debugging
    print("Parsed DataFrame:")
    print(df.head())

    # Save the DataFrame to a CSV file
    df.to_csv(output_file, index=False)

if __name__ == '__main__':
    log_file = 'alert_full.txt'  # Path to your Snort alert log file
    output_file = 'parsed_snort_logs.csv'

    df = parse_snort_log(log_file)
    if not df.empty:
        preprocess_and_save_to_csv(df, output_file)
        print(f'Parsed data saved to {output_file}')
    else:
        print("Error: Parsed DataFrame is empty. Please check the log file and parsing logic.")
