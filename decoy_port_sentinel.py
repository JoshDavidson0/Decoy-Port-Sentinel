import socket

import threading

from datetime import datetime

# ports is a collection of ports the client can connect to the server on.
ports = [2222, 8080, 9000, 2500]

def listen_on_port(active_port):
    # The following code creates a socket using IPv4 and stream based communication,
    # sets up an option at socket level to allow reuse of local addresses,
    # binds the socket to any available network interface using the current active port,
    # and tells the socket to start listening for incoming Transmission Control Protocol connections.
    # 2 connections can wait in the queue if they've havent been accepted yet, any further connections may be refused depending on timing.
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(('',active_port))
        s.listen(2)
        print(f"Listening on port {active_port}")

        # The Sentinel will continously accept connections until user presses enter to stop.
        # s.accept() will return a new socket object and a tuple containing the ip address, and active port number of the client.
        # client_socket is a new socket object for communicating with the client. 
        # client_ip is the ip address of the client. 
        while True:
            new_connection = s.accept()
            client_socket = new_connection[0] 
            client_ip = new_connection[1][0]

            # data will store 1024 raw bytes of the clients incoming message.
            # if the client closes the connection, a ConnectionResetError is called to avoid crashing the Sentinel and logged.
            with client_socket:
                print(f"Connection from {client_ip} at {datetime.now()}")
                try:
                    data = client_socket.recv(1024)
                except ConnectionResetError:
                    print(f"[!] Connection reset by {client_ip}")
                    with open("honeypot.log", "a") as log:
                        log.write(f"{datetime.now()} - {client_ip} - Port {active_port} - Connection reset\n")
                    return  # Exit the thread cleanly

                # If the length of the data sent by the client is longer than 1024 characters, the message will be sliced to 1024 characters.
                # risk_score will store an int value representing the severity of an incoming threat.
                # threat_keywords will store a collection of dangerous shell commands, if the client uses any, it will be marked by risk_score & logged.
                # decoded will store data as a readable string, if it cannot be decoded it will be marked by risk_score.
                # both the raw byte and decoded versions of the clients message will be printed for byte and string level text analysis.
                # The decoded client message will be logged with the date/time, ip address, port number, and risk score.
                if len(data) > 1024:
                    risk_score +=4
                    data = data[:1024]
                    print(f"[!] Dangerous Message Length from {client_ip}: length {len(data)}")

                print(f"Raw Byte Message: {repr(data)}")

                risk_score = 0
                threat_keywords = [b'\x90', b'\xCC', b'\x41', b'\x00', b'cmd', b'powershell', b'rm -rf', b'ping', b'scan', b'connect', b'echo'] 
                for keyword in threat_keywords:
                    if keyword in data :
                        risk_score += 10
                        print(f"[!] Threat keyword detected from {client_ip}: {keyword}")
                    
                try:
                    decoded_message = data.decode('utf-8').strip()
                except UnicodeDecodeError:
                    decoded_message = "[!] <undecodable>"
                    risk_score += 7
                    print(f"[!] Undecodable Message from {client_ip}: ")
                
                print(f"Decoded Message: {decoded_message}")
                with open("honeypot.log", "a") as log:
                    log.write(f"{datetime.now()} - {client_ip} - Port {active_port} - Payload: {decoded_message} - Total Risk Score: {risk_score}\n")
                    log.write("------------------------------------------------------------------------------------------------------------------------\n") 
                

                
# The following code will create a thread for each port, each thread will execute in the listen_on_port function.
# If the main theads finishes, the working threads will terminate.
for active_port in ports:
    port_thread = threading.Thread(target=listen_on_port, args=(active_port,))
    port_thread.daemon = True
    port_thread.start()

input("Press Enter to stop...\n")

