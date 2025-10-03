from datetime import datetime, timedelta

# The summary of entries will be for the past hour, one_hour_span will store the time one hour before the summary has been requested.
one_hour_span = datetime.now() - timedelta(hours=1)

# load_entries will take the honeypot.log file and the one_hour_span and check if the entries are within the recent hour, 
# if the entry is within the last hour it's information will be stored in a dictionary, which will be stored in entries,
# a list containing dictionary honeypot.log entries.
def load_entries(filename, one_hour_span):
    entries = []
    with open(filename, "r") as file:
        for line in file:
            entry_section = line.strip().split(" - ")
            if len(entry_section) != 5:
                continue
            try: 
                log_time = datetime.fromisoformat(entry_section[0])
            except ValueError:
                continue
            if log_time >= one_hour_span:
                if "Connection reset" in entry_section[4]:
                    continue
                entry = {"timestamp":entry_section[0], 
                         "Source IP": entry_section[1], 
                         "Port": entry_section[2].replace("Port ",""), 
                         "Payload": entry_section[3].replace("Payload: ",""), 
                         "Risk Score": int(entry_section[4].replace("Total Risk Score: ",""))}
                entries.append(entry)
    return entries

# session_logs will store the list of honeypot.log dictionary entries from the load_entries method.
session_logs = load_entries("honeypot.log", one_hour_span)

# summary will take the session_logs and report the number of total connections, risky connections, and unique ip addresses that 
# connected to the sentinel.
def summary(session_logs):
    total_connections = len(session_logs)
    num_risky_connections = 0
    unique_ips = set()
    for key in session_logs:
        if key["Risk Score"] > 0:
            num_risky_connections += 1
        unique_ips.add(key["Source IP"])
    num_unique_ips = len(unique_ips)
    print("Summary of the last hour:")
    print(f"Total Connections: {total_connections}")
    print(f"Risky Connections: {num_risky_connections}")
    print(f"Unique Source IPs: {num_unique_ips}")
   
summary(session_logs)