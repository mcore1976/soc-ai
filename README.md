This is an example that show how to build AI agent based self protection for the Ubuntu Linux system exposed to untrusted network like the Internet.

Following components are needed :

- Intrusion Detection system - Suricata
  
- AI LLM API provider - I am using Ollama and local models like gemma3:4b, but you can use whatever you have 
  
- Python script - the AI agent that reads Suricata log JSON file and sends the data to LLM for evaluation. The whole script has been written by AI
  
- Ubuntu Firewall - enforcement engine - once IDS discovered malicious communication, the UFW will be used to block it

Steps to build the whole solution :

--------------------------------------------------------------------------------------------------------------------

1. Install OLLAMA for you machine - an ddownload some LLM AI models 

curl -fsSL https://ollama.com/install.sh | sh

ollama pull gemma3:4b 

ollama list

---------------------------------------------------------------------------------------------------------------------

2. check the list of interfaces in your machine, and find the one exposed to untrusted network

ip a

8: enx582c80139263: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UNKNOWN group default qlen 1000
    link/ether 58:2c:80:13:92:63 brd ff:ff:ff:ff:ff:ff
    inet 192.168.1.100/24 brd 192.168.1.255 scope global dynamic noprefixroute enx582c80139263
     
-  TCPDUMP on this interface to see if this interface is really getting the malicious traffic 

sudo tcpdump -nn -i enx582c80139263

---------------------------------------------------------------------------------------------------------------------
3. Install ad configure Intrusion Detection System - Suricata IDS

a) Install the package

sudo apt install suricata -y

b)  decide which network you want to protect and put this info into Suricata configuration file,

- for example check your IP address

ip a

- in my case it is interface of my laptop 192.168.1.100

c) Edit Suricata configuration file to watch this interface and its network

sudo vi /etc/suricata/suricata.yaml

put your IP into HOME_NET

HOME_NET: "[192.168.1.100]"

- put you interface here - IMPORTANT !!!

sudo vi /etc/suricata/suricata.yaml

- look for this line and change interface name here :

af-packet:
  - interface: enx582c80139263

d) update the rules in Suricata with changes from the configuration file you edited

sudo suricata-update

e) enable it to run with the system startup

sudo systemctl enable --now suricata

f)  check if Sutricata is working

sudo ps -elf | grep suricata


--------------------------------------------------------------------------------------------------------------------------------------------

3. Enable FIREWALL so the script and LLM could write the rules for it 

a) clear the Ubuntu firewall from settings

sudo ufw reset

b) enable UFW again and check the status

sudo ufw enable

sudo ufw status

sudo ufw status verbose

--------------------------------------------------------------------------------------------------------------------------------------------

4. Prepare AI agent with Python script

- install Python and new library for ollama 

pip install --upgrade ollama

sudo pip install --upgrade ollama

- put the script into the notepad and save under soc.py

- run the script 

python3 soc.py

-----------------------------------------------------------------------------------------------------------------------------------------------

Link to the YouTube video : https://youtu.be/7uNzES1a5J0


