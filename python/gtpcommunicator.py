from ipaddress import IPv4Address
from scapy.all import *
from scapy.contrib.gtp_v2 import *
from scapy.all import conf
import threading
import queue
from scapy.layers.inet import IP, UDP

class GTPCommunicator:
    def __init__(self, interface):
        self.interface = interface
        self.response_queue = queue.Queue()
        self.socket = None
        self.stop_event = threading.Event()

    def receive_and_enqueue(self):
        while not self.stop_event.is_set():
            try:
                response = self.parse_response()
                if response is not None:
                    self.response_queue.put(response)
            except Exception as e:
                print(f"Error in receive_and_enqueue: {e}")

    def start_listener(self):
        try:
            self.socket = conf.L3socket(iface=self.interface)
        except OSError as e:
            logging.error(f"Error: {e}")
            logging.error(f"No such interface: {self.interface}")
            exit(1)
        receiver_thread = threading.Thread(target=self.receive_and_enqueue, daemon=True)
        receiver_thread.start()
    
    def stop_listener(self):
        try:
            if self.socket is not None:
                self.socket.close()
                self.socket = None
                logging.info("Listener stopped.")
            else:
                logging.warning("Listener is not running.")
        except Exception as e:
            logging.error(f"Error in stop_listener: {e}")    
    
    def send_request(self, base_pkt):
        if self.socket is not None:
            self.socket.send(base_pkt)
        else:
            logging.error("Socket not initialized. Start the listener first.")

    def get_response(self, timeout=1):
        try:
            response = self.response_queue.get(timeout=timeout)
            return response
        except queue.Empty:
            return None

    def parse_response(self):
        response = self.socket.recv(4096)
        if (
            response is not None
            and IP in response
            and UDP in response
            and GTPHeader in response
        ):
            return response
        return None
    
    def process_response(self,response):
        if GTPV2CreateSessionResponse in response:
            pdn_ip_address = self.parse_ipv4_address(response)
            gre_key = self.parse_gre_key_from_response(response)
            return(pdn_ip_address,gre_key)
        elif GTPV2ModifyBearerResponse in response:
            cause_and_teid = self.cause_modify_bearer_response(response)
            return(cause_and_teid)
        elif GTPV2DeleteSessionResponse in response:
            cause = self.cause_delete_session_response(response)
            return(response)  
        else :
            return None  
    
    def parse_ipv4_address(self,response):
        gtp_response = response[GTPHeader]
        ie_list = gtp_response[GTPV2CreateSessionResponse].getfieldval("IE_list")
        for ie in ie_list:
                if isinstance(ie, IE_PAA):
                    ipv4_address = IPv4Address(ie.ipv4)
                    return ipv4_address
        return None

    def parse_gre_key_from_response(self,response):
        fteid_ie = response[GTPV2CreateSessionResponse].getlayer(IE_FTEID)
        if fteid_ie:
            gre_key = fteid_ie.GRE_Key
            return gre_key
        return None
        
    def cause_modify_bearer_response(self,response):
        IE_Cause= response[GTPV2ModifyBearerResponse].IE_list[0].Cause
        teid=response[GTPHeader].teid
        return IE_Cause,teid

    def cause_delete_session_response(self,response):
        IE_Cause= response[GTPV2DeleteSessionResponse].IE_list[0].Cause
        return IE_Cause

