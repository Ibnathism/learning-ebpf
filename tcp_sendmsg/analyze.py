import re
from collections import defaultdict
from datetime import datetime

# Function to read the log file and extract PIDs with packet counts at the end of each minute interval
def analyze_log_by_interval(file_path):
    pid_interval_counts = defaultdict(dict)
    
    # Regular expression to match the timestamp and PID pattern
    log_pattern = re.compile(r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) - PID (\d+): (\d+) packets')
    
    # Read the log file
    with open(file_path, 'r') as file:
        for line in file:
            match = log_pattern.search(line)
            if match:
                timestamp = datetime.strptime(match.group(1), '%Y-%m-%d %H:%M:%S')
                pid = int(match.group(2))
                packets = int(match.group(3))
                
                # Round down the timestamp to the nearest minute
                interval = timestamp.replace(second=0)
                
                # Store the latest packet count for the PID in that interval
                pid_interval_counts[pid][interval] = packets

    return pid_interval_counts

# Specify the path to your log file
file_path = 'packet_counts.log'

# Analyze the log file
pid_interval_counts = analyze_log_by_interval(file_path)

# Print the results
for pid, intervals in pid_interval_counts.items():
    print(f"PID {pid}:")
    for interval, packet_count in sorted(intervals.items()):
        print(f"  {interval}: {packet_count} packets")
