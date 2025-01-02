This Python script is a simple HTTP traffic sniffer built using the Scapy library. It captures and analyzes HTTP requests on a specified network interface. The script can help in monitoring web traffic and identifying potential security issues, such as exposed credentials.

**Features** \
Network Interface Selection: Automatically lists available network interfaces and allows the user to select one for sniffing. \
HTTP Request Capture: Captures HTTP requests, displaying the host, path, and destination IP address. \
Credential Detection: Scans HTTP payloads for potential sensitive information such as usernames and passwords. 

**Requirements** \
Python 3.x \
Scapy library \
npcap (for windows)

**Clone the repository**
```
git clone https://github.com/Dilshanrawishka/S_Net_Sniffer
cd repository
```

**Navigate to the project directory**
```
cd path to project directory
```

**Run the script**
```
python sniffer.py -i <interface>
python sniffer.py
```

**in linux** \
**Install Scapy if you haven't already**
```
pip install scapy
```
**Run the script**
```bash
sudo python sniffer.py
sudo python sniffer.py -i eth0
```
