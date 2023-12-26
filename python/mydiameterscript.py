#Interactive Diameter Client
import socket
import sys
import os
import diameter
import time
import _thread
import threading

global recv_ip, CCRSessionid, CCRDest_host, CCRDest_realm, CCRueIp ,clientsocket

recv_ip = "127.0.0.10"                                                         #IP of this Machine
CCRSessionid = None
CCRDest_host = None
CCRDest_realm = None
CCRueIp = None
clientsocket= None

diameter_host ="hss01.localdomian"                                                        #Diameter Host of this Machine
realm ="localdomain"                                         #Diameter Realm of this machine
DestinationHost = "smf.localdomian"                                             #Diameter Host of Destination
DestinationRealm = "localdomian"                                                #Diameter Realm of Destination
hostname = "127.0.0.4"                                                         #IP of Remote Diameter Host
mcc = "001"                                                                     #Mobile Country Code
mnc = "01"                                                                      #Mobile Network Code
transport = 'TCP'                                                              #Transport Type - TCP or SCTP (SCTP Support is basic)

charging_rules = {
    'rule_name': 'Rule1',
    'tft': [
        {'direction': 1, 'tft_string': 'permit out 17 from 172.22.0.16 49000 to 192.168.101.3 50046'},
        {'direction': 2, 'tft_string': 'permit out 17 from 172.22.0.16 49000 to 192.168.101.3 50046'}
    ],
    'qci': 5,
    'arp_priority': 2,
    'arp_preemption_capability': False,
    'arp_preemption_vulnerability': True,
    'mbr_ul': 1024,
    'mbr_dl': 2048,
    'gbr_ul': 512,
    'gbr_dl': 1024,
    'precedence': 3,
    'rating_group': None
}

diameter = diameter.Diameter(diameter_host, realm, 'PyHSS-client', str(mcc), str(mnc))

def ReadBuffer(clientsocket): 
            global CCRSessionid, CCRDest_host, CCRDest_realm, CCRueIp
            SendRequest(clientsocket, diameter.Request_257())
            while True:
                try:
                        data = clientsocket.recv(32)
                        packet_length = diameter.decode_diameter_packet_length(data)            #Calculate length of packet from start of packet
                        data_sum = data + clientsocket.recv(packet_length - 32)                 #Recieve remainder of packet from buffer
                        packet_vars, avps = diameter.decode_diameter_packet(data_sum)
                        if  int(packet_vars['command_code']) == 280 and diameter.hex_to_bin(packet_vars['flags'])[0] == "1":  # Recieve DWR ,send DWA
                            print("Received DWR - Sending DWA to " +str(hostname) )
                            SendRequest(clientsocket,diameter.Answer_280(packet_vars, avps))
                            continue
                        print("Got response from " + str(hostname))
                        for keys in packet_vars:
                            print("\t" + str(keys) + "\t" + str(packet_vars[keys]))
                        print("Command Code: " + str(packet_vars['command_code']))
                        
                        if int(packet_vars['command_code']) == 272:
                            print("Received CCR")
                            for keys in packet_vars:
                                print("\t" + str(keys) + "\t" + str(packet_vars[keys]))
                            SendRequest(clientsocket,diameter.Answer_16777238_272(packet_vars, avps))
                            CCRSessionid=bytes.fromhex(diameter.get_avp_data(avps,263)[0]).decode('utf-8')
                            CCRDest_host=bytes.fromhex(diameter.get_avp_data(avps,264)[0]).decode('utf-8')
                            CCRDest_realm=bytes.fromhex(diameter.get_avp_data(avps,296)[0]).decode('utf-8')
                            CCRueIp=str(diameter.hex_to_ip(diameter.get_avp_data(avps,8)[0]))
                        if int(packet_vars['command_code']) == 265:
                            print("Recived AA Request sending AA Answer")
                            AARSessionid=bytes.fromhex(diameter.get_avp_data(avps,263)[0]).decode('utf-8')
                            SendRequest(clientsocket,diameter.Answer_16777236_265(packet_vars, avps))
                        if int(packet_vars['command_code']) == 280:
                            flags_bin = diameter.hex_to_bin(packet_vars['flags'])
                            print("Flags are " + str(flags_bin)) 
                            print("Received DWA")
                        if int(packet_vars['command_code']) == 257:
                            #Check if Request or Response
                            flags_bin = diameter.hex_to_bin(packet_vars['flags'])
                            print("Flags are " + str(flags_bin)) 
                            #ToDo - check first byte only
                            if flags_bin[0] == '1':
                                print("Received CER - Sending CEA")
                                SendRequest(clientsocket,diameter.Answer_257(packet_vars, avps, recv_ip))
                            else:
                                print("Is CEA")
                                                                            
                except KeyboardInterrupt:
                    print("User exited background loop")
                    break                       
                except Exception as e:
                    time.sleep(0.1)
                    continue 


def establish_diam_tcp_connection():
    try:
        global clientsocket
        
        if transport == "TCP":
            clientsocket = socket.socket()
            clientsocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            # clientsocket.bind((recv_ip[0], 3868))
        elif transport == "SCTP":
            import sctp
            clientsocket = sctp.sctpsocket_tcp(socket.AF_INET)
        else:
            print(str(transport) + " is not a valid transport type, exiting.")
            sys.exit()

        clientsocket.connect((hostname, 3868))
        _thread.start_new_thread(ReadBuffer, (clientsocket,))

    except Exception as e:
        print("Failed to connect to the server - Error: " + str(e))

def SendRequest(clientsocket,request):
    clientsocket.sendall(bytes.fromhex(request))
    #ReadBuffer()

def send_auth_request():
    global CCRSessionid, CCRDest_host, CCRDest_realm, CCRueIp
    installchargingRuleAction='install'
    SendRequest(clientsocket,diameter.Request_16777238_258(sessionId=CCRSessionid,servingPgw=CCRDest_host,servingRealm=CCRDest_realm,chargingRules=charging_rules,ueIp=CCRueIp,chargingRuleAction=installchargingRuleAction))
    
def send_delete_auth_request():
    global CCRSessionid, CCRDest_host, CCRDest_realm, CCRueIp
    installchargingRuleAction='remove'
    chargingRuleName='Rule1'
    SendRequest(clientsocket,diameter.Request_16777238_258(sessionId=CCRSessionid,servingPgw=CCRDest_host,servingRealm=CCRDest_realm,chargingRules=None,ueIp=CCRueIp,chargingRuleAction=installchargingRuleAction,chargingRuleName=chargingRuleName))    
    
def close_tcp_session():
    global clientsocket
    if clientsocket:
        clientsocket.close()
            