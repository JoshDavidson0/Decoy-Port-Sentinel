# Decoy Port Sentinel
A Python based passive Honeypot that simulates vulnerable services and logs connection attempts. 

# Features
- Wireshark integration for network packet capture and analysis. 
- Threat Scoring and metadata loggin to demonstrate intrusion awareness.
- Timestamp-based session filtering and summary generation to support log analysis. 
- TCP socket communication with client. 
- Threads integrated for multi-port capabilities.
- Efficient logging of all connection attempts with organized formatting. 
- Hourly summary reporting for recent connection activity and threat insights.

# How to Run
- Run the Sentinel using python decoy_port_sentinel.py
- Use any terminal to send payloads to the sentinel via any of the 4 port numbers provided in decoy_port_sentinel.py
- For example you can pipe payloads using Netcat: echo -n "This is a payload" | ncat localhost 2222
- View the honeypot.log file to analyze connection and payload history.
- Generate a summary report of the past hour using python entry_log.py
