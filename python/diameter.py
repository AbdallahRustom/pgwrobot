#Diameter Packet Decoder / Encoder & Tools
import socket
import binascii
import math
import uuid
import os
import ipaddress
import jinja2
from messaging import RedisMessaging
import yaml
import json
import time
import traceback

def get_static_charging_rules():
    return {
        'apn_data': {
            'qci': 1,  # QoS Class Identifier
            'arp_priority': 2,  # Allocation and Retention Priority (ARP) Priority Level
            'arp_preemption_capability': True,  # ARP Preemption Capability
            'arp_preemption_vulnerability': True,  # ARP Preemption Vulnerability
            'apn_ambr_ul': 1000000,  # APN-AMBR for UL (bits per second)
            'apn_ambr_dl': 2000000,  # APN-AMBR for DL (bits per second)
        },
        'charging_rules': [
            {
                'rule_name': 'DefaultRule',
                'rule_type': 'QoS',
                'qci': 1,  # QoS Class Identifier
                'max_requested_bandwidth_ul': 500000,  # Max Requested Bandwidth UL (bits per second)
                'max_requested_bandwidth_dl': 1000000,  # Max Requested Bandwidth DL (bits per second)
            },
            {
                'rule_name': 'PremiumRule',
                'rule_type': 'QoS',
                'qci': 2,
                'max_requested_bandwidth_ul': 1000000,
                'max_requested_bandwidth_dl': 2000000,
            },
        ]
    }
    
class Diameter:

    def __init__(self, originHost: str="hss01", originRealm: str="epc.mnc999.mcc999.3gppnetwork.org", productName: str="PyHSS", mcc: str="999", mnc: str="999", redisMessaging=None):
        script_dir = os.path.dirname(__file__)
        config_path = os.path.join(script_dir, "config.yaml")
        with open(config_path, 'r') as stream:
            self.config = (yaml.safe_load(stream))

        self.OriginHost = self.string_to_hex(originHost)
        self.OriginRealm = self.string_to_hex(originRealm)
        self.ProductName = self.string_to_hex(productName)
        self.MNC = str(mnc)
        self.MCC = str(mcc)
        # self.logTool = logTool

        self.redisUseUnixSocket = self.config.get('redis', {}).get('useUnixSocket', False)
        self.redisUnixSocketPath = self.config.get('redis', {}).get('unixSocketPath', '/var/run/redis/redis-server.sock')
        self.redisHost = self.config.get('redis', {}).get('host', 'localhost')
        self.redisPort = self.config.get('redis', {}).get('port', 6379)
        if redisMessaging:
            self.redisMessaging = redisMessaging
        else:
            self.redisMessaging = RedisMessaging(host=self.redisHost, port=self.redisPort, useUnixSocket=self.redisUseUnixSocket, unixSocketPath=self.redisUnixSocketPath)

        #self.database = Database(logTool=logTool)
        self.diameterRequestTimeout = int(self.config.get('hss', {}).get('diameter_request_timeout', 10))

        self.templateLoader = jinja2.FileSystemLoader(searchpath="../")
        self.templateEnv = jinja2.Environment(loader=self.templateLoader)

        self.diameterResponseList = [
                {"commandCode": 257, "applicationId": 0, "flags": 80, "responseMethod": self.Answer_257, "failureResultCode": 5012 ,"requestAcronym": "CER", "responseAcronym": "CEA", "requestName": "Capabilites Exchange Request", "responseName": "Capabilites Exchange Answer"},
                {"commandCode": 280, "applicationId": 0, "flags": 80, "responseMethod": self.Answer_280, "failureResultCode": 5012 ,"requestAcronym": "DWR", "responseAcronym": "DWA", "requestName": "Device Watchdog Request", "responseName": "Device Watchdog Answer"},
                {"commandCode": 272, "applicationId": 16777238, "responseMethod": self.Answer_16777238_272, "failureResultCode": 5012 ,"requestAcronym": "CCR", "responseAcronym": "CCA", "requestName": "Credit Control Request", "responseName": "Credit Control Answer"},
                {"commandCode": 265, "applicationId": 16777236, "responseMethod": self.Answer_16777236_265, "failureResultCode": 4100 ,"requestAcronym": "AAR", "responseAcronym": "AAA", "requestName": "AA Request", "responseName": "AA Answer"},
            ]

        self.diameterRequestList = [
                {"commandCode": 258, "applicationId": 16777238, "requestMethod": self.Request_16777238_258, "failureResultCode": 5012 ,"requestAcronym": "RAR", "responseAcronym": "RAA", "requestName": "Re Auth Request", "responseName": "Re Auth Answer"},
                {"commandCode": 272, "applicationId": 16777238, "requestMethod": self.Request_16777238_272, "failureResultCode": 5012 ,"requestAcronym": "CCR", "responseAcronym": "CCA", "requestName": "Credit Control Request", "responseName": "Credit Control Answer"},
        ]

    #Generates rounding for calculating padding
    def myround(self, n, base=4):
        if(n > 0):
            return math.ceil(n/4.0) * 4
        elif( n < 0):
            return math.floor(n/4.0) * 4
        else:
            return 4

    #Converts a dotted-decimal IPv4 address or IPV6 address to hex
    def ip_to_hex(self, ip):
        #Determine IPvX version:
        if "." in ip:
            ip = ip.split('.')
            ip_hex = "0001"         #IPv4
            ip_hex = ip_hex + str(format(int(ip[0]), 'x').zfill(2))
            ip_hex = ip_hex + str(format(int(ip[1]), 'x').zfill(2))
            ip_hex = ip_hex + str(format(int(ip[2]), 'x').zfill(2))
            ip_hex = ip_hex + str(format(int(ip[3]), 'x').zfill(2))
        else:
            ip_hex = "0002"         #IPv6
            ip_hex += format(ipaddress.IPv6Address(ip), 'X')
        return ip_hex
    
    def hex_to_int(self, hex):
        return int(str(hex), base=16)


    #Converts a hex formatted IPv4 address or IPV6 address to dotted-decimal 
    def hex_to_ip(self, hex_ip):
        if len(hex_ip) == 8:
            octet_1 = int(str(hex_ip[0:2]), base=16)
            octet_2 = int(str(hex_ip[2:4]), base=16)
            octet_3 = int(str(hex_ip[4:6]), base=16)
            octet_4 = int(str(hex_ip[6:8]), base=16)
            return str(octet_1) + "." + str(octet_2) + "." + str(octet_3) + "." + str(octet_4)
        elif len(hex_ip) == 32:
            n=4
            ipv6_split = [hex_ip[idx:idx + n] for idx in range(0, len(hex_ip), n)]
            ipv6_str = ''
            for octect in ipv6_split:
                ipv6_str += str(octect).lstrip('0') + ":"
            #Strip last Colon
            ipv6_str = ipv6_str[:-1]
            return ipv6_str

    #Converts string to hex
    def string_to_hex(self, string):
        string_bytes = string.encode('utf-8')
        return str(binascii.hexlify(string_bytes), 'ascii')

    #Converts int to hex padded to required number of bytes
    def int_to_hex(self, input_int, output_bytes):
        
        return format(input_int,"x").zfill(output_bytes*2)

    #Converts Hex byte to Binary
    def hex_to_bin(self, input_hex):
        return bin(int(str(input_hex), 16))[2:].zfill(8)

    #Generates a valid random ID to use
    def generate_id(self, length):
        length = length * 2
        return str(uuid.uuid4().hex[:length])

    def Reverse(self, str):
        stringlength=len(str)
        slicedString=str[stringlength::-1]
        return (slicedString)

    def DecodePLMN(self, plmn):
        # self.logTool.log(service='HSS', level='debug', message="Decoded PLMN: " + str(plmn), redisClient=self.redisMessaging)
        mcc = self.Reverse(plmn[0:2]) + self.Reverse(plmn[2:4]).replace('f', '')
        # self.logTool.log(service='HSS', level='debug', message="Decoded MCC: " + mcc, redisClient=self.redisMessaging)

        mnc = self.Reverse(plmn[4:6])
        self.logTool.log(service='HSS', level='debug', message="Decoded MNC: " + mnc, redisClient=self.redisMessaging)
        return mcc, mnc

    def EncodePLMN(self, mcc, mnc):
        plmn = list('XXXXXX')
        plmn[0] = self.Reverse(mcc)[1]
        plmn[1] = self.Reverse(mcc)[2]
        plmn[2] = "f"
        plmn[3] = self.Reverse(mcc)[0]
        plmn[4] = self.Reverse(mnc)[0]
        plmn[5] = self.Reverse(mnc)[1]
        plmn_list = plmn
        plmn = ''
        for bits in plmn_list:
            plmn = plmn + bits
        self.logTool.log(service='HSS', level='debug', message="Encoded PLMN: " + str(plmn), redisClient=self.redisMessaging)
        return plmn

    def TBCD_special_chars(self, input):
        self.logTool.log(service='HSS', level='debug', message="Special character possible in " + str(input), redisClient=self.redisMessaging)
        if input == "*":
            self.logTool.log(service='HSS', level='debug', message="Found * - Returning 1010", redisClient=self.redisMessaging)
            return "1010"
        elif input == "#":
            self.logTool.log(service='HSS', level='debug', message="Found # - Returning 1011", redisClient=self.redisMessaging)
            return "1011"
        elif input == "a":
            self.logTool.log(service='HSS', level='debug', message="Found a - Returning 1100", redisClient=self.redisMessaging)
            return "1100"
        elif input == "b":
            self.logTool.log(service='HSS', level='debug', message="Found b - Returning 1101", redisClient=self.redisMessaging)
            return "1101"
        elif input == "c":
            self.logTool.log(service='HSS', level='debug', message="Found c - Returning 1100", redisClient=self.redisMessaging)
            return "1100"      
        else:
            binform = "{:04b}".format(int(input))
            self.logTool.log(service='HSS', level='debug', message="input " + str(input) + " is not a special char, converted to bin: " + str(binform), redisClient=self.redisMessaging)
            return (binform)

    def TBCD_encode(self, input):
        self.logTool.log(service='HSS', level='debug', message="TBCD_encode input value is " + str(input), redisClient=self.redisMessaging)
        offset = 0
        output = ''
        matches = ['*', '#', 'a', 'b', 'c']
        while offset < len(input):
            if len(input[offset:offset+2]) == 2:
                self.logTool.log(service='HSS', level='debug', message="processing bits " + str(input[offset:offset+2]) + " at position offset " + str(offset), redisClient=self.redisMessaging)
                bit = input[offset:offset+2]    #Get two digits at a time
                bit = bit[::-1]                 #Reverse them
                #Check if *, #, a, b or c
                if any(x in bit for x in matches):
                    self.logTool.log(service='HSS', level='debug', message="Special char in bit " + str(bit), redisClient=self.redisMessaging)
                    new_bit = ''
                    new_bit = new_bit + str(self.TBCD_special_chars(bit[0]))
                    new_bit = new_bit + str(self.TBCD_special_chars(bit[1]))
                    self.logTool.log(service='HSS', level='debug', message="Final bin output of new_bit is " + str(new_bit), redisClient=self.redisMessaging)
                    bit = hex(int(new_bit, 2))[2:]      #Get Hex value
                    self.logTool.log(service='HSS', level='debug', message="Formatted as Hex this is " + str(bit), redisClient=self.redisMessaging)
                output = output + bit
                offset = offset + 2
            else:
                #If odd-length input
                last_digit = str(input[offset:offset+2])
                #Check if *, #, a, b or c
                if any(x in last_digit for x in matches):
                    self.logTool.log(service='HSS', level='debug', message="Special char in bit " + str(bit), redisClient=self.redisMessaging)
                    new_bit = ''
                    new_bit = new_bit + '1111'      #Add the F first
                    #Encode the symbol into binary and append it to the new_bit var
                    new_bit = new_bit + str(self.TBCD_special_chars(last_digit))
                    self.logTool.log(service='HSS', level='debug', message="Final bin output of new_bit is " + str(new_bit), redisClient=self.redisMessaging) 
                    bit = hex(int(new_bit, 2))[2:]      #Get Hex value
                    self.logTool.log(service='HSS', level='debug', message="Formatted as Hex this is " + str(bit), redisClient=self.redisMessaging)
                else:
                    bit = "f" + last_digit
                offset = offset + 2
                output = output + bit
        self.logTool.log(service='HSS', level='debug', message="TBCD_encode final output value is " + str(output), redisClient=self.redisMessaging)
        return output

    def TBCD_decode(self, input):
        self.logTool.log(service='HSS', level='debug', message="TBCD_decode Input value is " + str(input), redisClient=self.redisMessaging)
        offset = 0
        output = ''
        while offset < len(input):
            if "f" not in input[offset:offset+2]:
                bit = input[offset:offset+2]    #Get two digits at a time
                bit = bit[::-1]                 #Reverse them
                output = output + bit
                offset = offset + 2
            else:   #If f in bit strip it
                bit = input[offset:offset+2]
                output = output + bit[1]
                self.logTool.log(service='HSS', level='debug', message="TBCD_decode output value is " + str(output), redisClient=self.redisMessaging)
                return output

    #Generates an AVP with inputs provided (AVP Code, AVP Flags, AVP Content, Padding)
    #AVP content must already be in HEX - This can be done with binascii.hexlify(avp_content.encode())
    def generate_avp(self, avp_code, avp_flags, avp_content):
        avp_code = format(avp_code,"x").zfill(8)
        
        avp_length = 1 ##This is a placeholder that's overwritten later

        #AVP Must always be a multiple of 4 - Round up to nearest multiple of 4 and fill remaining bits with padding
        avp = str(avp_code) + str(avp_flags) + str("000000") + str(avp_content)
        avp_length = int(len(avp)/2)

        if avp_length % 4  == 0:    #Multiple of 4 - No Padding needed
            avp_padding = ''
        else:                       #Not multiple of 4 - Padding needed
            rounded_value = self.myround(avp_length)
            avp_padding = format(0,"x").zfill(int( rounded_value - avp_length) * 2)

        avp = str(avp_code) + str(avp_flags) + str(format(avp_length,"x").zfill(6)) + str(avp_content) + str(avp_padding)
        return avp

    #Generates an AVP with inputs provided (AVP Code, AVP Flags, AVP Content, Padding)
    #AVP content must already be in HEX - This can be done with binascii.hexlify(avp_content.encode())
    def generate_vendor_avp(self, avp_code, avp_flags, avp_vendorid, avp_content):
        avp_code = format(avp_code,"x").zfill(8)
        
        avp_length = 1 ##This is a placeholder that gets overwritten later

        avp_vendorid = format(int(avp_vendorid),"x").zfill(8)
        
        #AVP Must always be a multiple of 4 - Round up to nearest multiple of 4 and fill remaining bits with padding
        avp = str(avp_code) + str(avp_flags) + str("000000") + str(avp_vendorid) + str(avp_content)
        avp_length = int(len(avp)/2)

        if avp_length % 4  == 0:    #Multiple of 4 - No Padding needed
            avp_padding = ''
        else:                       #Not multiple of 4 - Padding needed
            rounded_value = self.myround(avp_length)
            # self.logTool.log(service='HSS', level='debug', message="Rounded value is " + str(rounded_value), redisClient=self.redisMessaging)
            # self.logTool.log(service='HSS', level='debug', message="Has " + str( int( rounded_value - avp_length)) + " bytes of padding", redisClient=self.redisMessaging)
            avp_padding = format(0,"x").zfill(int( rounded_value - avp_length) * 2)


        
        avp = str(avp_code) + str(avp_flags) + str(format(avp_length,"x").zfill(6)) + str(avp_vendorid) + str(avp_content) + str(avp_padding)
        return avp

    def generate_diameter_packet(self, packet_version, packet_flags, packet_command_code, packet_application_id, packet_hop_by_hop_id, packet_end_to_end_id, avp):
        try:
            packet_length = 228
            packet_length = format(packet_length,"x").zfill(6)
        
            packet_command_code = format(packet_command_code,"x").zfill(6)
            
            packet_application_id = format(packet_application_id,"x").zfill(8)
            
            packet_hex = packet_version + packet_length + packet_flags + packet_command_code + packet_application_id + packet_hop_by_hop_id + packet_end_to_end_id + avp
            packet_length = int(round(len(packet_hex))/2)
            packet_length = format(packet_length,"x").zfill(6)
            
            packet_hex = packet_version + packet_length + packet_flags + packet_command_code + packet_application_id + packet_hop_by_hop_id + packet_end_to_end_id + avp
            return packet_hex
        except Exception as e:
            self.logTool.log(service='HSS', level='error', message=f"[diameter.py] [generate_diameter_packet] Exception: {e}", redisClient=self.redisMessaging)



    def roundUpToMultiple(self, n, multiple):
        return ((n + multiple - 1) // multiple) * multiple


    def validateSingleAvp(self, data) -> bool:
        """
        Attempts to validate a single hex string diameter AVP as being an AVP.
        """
        try:
            avpCode = int(data[0:8], 16)
            # The next byte contains the AVP Flags
            avpFlags = data[8:10]
            # The next 3 bytes contain the AVP Length
            avpLength = int(data[10:16], 16)
            if avpFlags not in ['80', '40', '20', '00', 'c0']:
                return False
            if int(len(data[16:]) / 2) < ((avpLength - 8)):
                return False
            return True
        except Exception as e:
            return False

    def decode_diameter_packet(self, data):
        """
        Handles decoding of a full diameter packet.
        """
        packet_vars = {}
        avps = []

        if type(data) is bytes:
            data = data.hex()
        # One byte is 2 hex characters
        # First Byte is the Diameter Packet Version
        packet_vars['packet_version'] = data[0:2]
        # Next 3 Bytes are the length of the entire Diameter packet
        packet_vars['length'] = int(data[2:8], 16)
        # Next Byte is the Diameter Flags
        packet_vars['flags'] = data[8:10]
        packet_vars['flags_bin'] = bin(int(data[8:10], 16))[2:].zfill(8)
        # Next 3 Bytes are the Diameter Command Code
        packet_vars['command_code'] = int(data[10:16], 16)
        # Next 4 Bytes are the Application Id
        packet_vars['ApplicationId'] = int(data[16:24], 16)
        # Next 4 Bytes are the Hop By Hop Identifier
        packet_vars['hop-by-hop-identifier'] = data[24:32]
        # Next 4 Bytes are the End to End Identifier
        packet_vars['end-to-end-identifier'] = data[32:40]


        lengthOfDiameterVars = int(len(data[:40]) / 2)

        #Length of all AVPs, in bytes
        avpLength = int(packet_vars['length'] - lengthOfDiameterVars)
        avpCharLength = int((avpLength * 2))
        remaining_avps = data[40:]

        avps = self.decodeAvpPacket(remaining_avps)

        return packet_vars, avps

    def decodeAvpPacket(self, data):
        """
        Returns a list of decoded AVP Packet dictionaries.
        This function is called at a high frequency, decoding methods should stick to iteration and not recursion, to avoid a memory leak.
        """
        # Note: After spending hours on this, I'm leaving the following technical debt:
        # Subavps and all their descendents are lifted up, flat, side by side into the parent's sub_avps list.
        # It's definitely possible to keep the nested tree structure, if anyone wants to improve this function. But I can't figure out a simple way to do so, without invoking recursion.


        # Our final list of AVP Dictionaries, which will be returned once processing is complete.
        processed_avps = []
        # Initialize a failsafe counter, to prevent packets that pass validation but aren't AVPs from causing an infinite loop
        failsafeCounter = 0

        # If the avp data is 8 bytes (16 chars) or less, it's invalid.
        if len(data) < 16:
            return []

        # Working stack to aid in iterative processing of sub-avps.
        subAvpUnprocessedStack = []

        # Keep processing AVPs until they're all dealt with
        while len(data) > 16:
            try:
                failsafeCounter += 1

                if failsafeCounter > 100:
                    break
                avp_vars = {}
                # The first 4 bytes contains the AVP code
                avp_vars['avp_code'] = int(data[0:8], 16)
                # The next byte contains the AVP Flags
                avp_vars['avp_flags'] = data[8:10]
                # The next 3 bytes contains the AVP Length
                avp_vars['avp_length'] = int(data[10:16], 16)
                # The remaining bytes (until the end, defined by avp_length) is the AVP payload.
                # Padding is excluded from avp_length. It's calculated separately, and unknown by the AVP itself.
                # We calculate the avp payload length (in bytes) by subtracting 8, because the avp headers are always 8 bytes long. 
                # The result is then multiplied by 2 to give us chars.
                avpPayloadLength = int((avp_vars['avp_length'])*2)

                # Work out our vendor id and add the payload itself (misc_data)
                if avp_vars['avp_flags'] == 'c0' or avp_vars['avp_flags'] == '80':
                    avp_vars['vendor_id'] = int(data[16:24], 16)
                    avp_vars['misc_data'] = data[24:avpPayloadLength]
                else:
                    avp_vars['vendor_id'] = ''
                    avp_vars['misc_data'] = data[16:avpPayloadLength]

                payloadContainsSubAvps = self.validateSingleAvp(avp_vars['misc_data'])
                if payloadContainsSubAvps:
                    # If the payload contains sub or grouped AVPs, append misc_data to the subAvpUnprocessedStack to start working through one or more subavp
                    subAvpUnprocessedStack.append(avp_vars["misc_data"])
                    avp_vars["misc_data"] = ''

                # Rounds up the length to the nearest multiple of 4, which we can differential against the avp length to give us the padding length (if required)
                avp_padded_length = int((self.roundUpToMultiple(avp_vars['avp_length'], 4)))
                avpPaddingLength = ((avp_padded_length - avp_vars['avp_length']) * 2)

                # Initialize a blank sub_avps list, regardless of whether or not we have any sub avps.
                avp_vars['sub_avps'] = []

                while payloadContainsSubAvps:
                    # Increment our failsafe counter, which will fail after 100 tries. This prevents a rare validation error from causing the function to hang permanently.
                    failsafeCounter += 1

                    if failsafeCounter > 100:
                        break
                    
                    # Pop the sub avp data from the list (remove from the end)
                    sub_avp_data = subAvpUnprocessedStack.pop()

                    # Initialize our sub avp dictionary, and grab the usual values
                    sub_avp = {}
                    sub_avp['avp_code'] = int(sub_avp_data[0:8], 16)
                    sub_avp['avp_flags'] = sub_avp_data[8:10]
                    sub_avp['avp_length'] = int(sub_avp_data[10:16], 16)
                    sub_avpPayloadLength = int((sub_avp['avp_length'])*2)

                    if sub_avp['avp_flags'] == 'c0' or sub_avp['avp_flags'] == '80':
                        sub_avp['vendor_id'] = int(sub_avp_data[16:24], 16)
                        sub_avp['misc_data'] = sub_avp_data[24:sub_avpPayloadLength]
                    else:
                        sub_avp['vendor_id'] = ''
                        sub_avp['misc_data'] = sub_avp_data[16:sub_avpPayloadLength]

                    containsSubAvps = self.validateSingleAvp(sub_avp["misc_data"])
                    if containsSubAvps:
                        subAvpUnprocessedStack.append(sub_avp["misc_data"])
                        sub_avp["misc_data"] = ''
                    
                    avp_vars['sub_avps'].append(sub_avp)

                    sub_avp_padded_length = int((self.roundUpToMultiple(sub_avp['avp_length'], 4)))
                    subAvpPaddingLength = ((sub_avp_padded_length - sub_avp['avp_length']) * 2)

                    sub_avp_data = sub_avp_data[sub_avpPayloadLength+subAvpPaddingLength:]
                    containsNestedSubAvps = self.validateSingleAvp(sub_avp_data)

                    # Check for nested sub avps and bring them to the top of the stack, for further processing.
                    if containsNestedSubAvps:
                        subAvpUnprocessedStack.append(sub_avp_data)
                    
                    if containsSubAvps or containsNestedSubAvps:
                        payloadContainsSubAvps = True
                    else:
                        payloadContainsSubAvps = False

                if avpPaddingLength > 0:
                    processed_avps.append(avp_vars)
                    data = data[avpPayloadLength+avpPaddingLength:]
                else:
                    processed_avps.append(avp_vars)
                    data = data[avpPayloadLength:]
            except Exception as e:
                print(e)
                continue

        return processed_avps

    def get_avp_data(self, avps, avp_code):               #Loops through list of dicts generated by the packet decoder, and returns the data for a specific AVP code in list (May be more than one AVP with same code but different data)
        misc_data = []
        for avpObject in avps:
            if int(avpObject['avp_code']) == int(avp_code):
                if len(avpObject['misc_data']) == 0:
                    misc_data.append(avpObject['sub_avps'])
                else:
                    misc_data.append(avpObject['misc_data'])
            if 'sub_avps' in avpObject:
                for sub_avp in avpObject['sub_avps']:
                    if int(sub_avp['avp_code']) == int(avp_code):
                        misc_data.append(sub_avp['misc_data'])
        return misc_data

    def decode_diameter_packet_length(self, data):
        packet_vars = {}
        data = data.hex()
        packet_vars['packet_version'] = data[0:2]
        packet_vars['length'] = int(data[2:8], 16)
        if packet_vars['packet_version'] == "01":
            return packet_vars['length']
        else:
            return False

    def getPeerType(self, originHost: str) -> str:
        try:
            peerTypes = ['mme', 'pgw', 'pcscf', 'icscf', 'scscf', 'hss', 'ocs', 'dra']

            for peer in peerTypes:
                if peer in originHost.lower():
                    return peer
            
        except Exception as e:
            return ''

    def getConnectedPeersByType(self, peerType: str) -> list:
        try:
            peerType = peerType.lower()
            peerTypes = ['mme', 'pgw', 'pcscf', 'icscf', 'scscf', 'hss', 'ocs', 'dra']

            if peerType not in peerTypes:
                return []
            filteredConnectedPeers = []
            activePeers = json.loads(self.redisMessaging.getValue(key="ActiveDiameterPeers").decode())

            for key, value in activePeers.items():
                if activePeers.get(key, {}).get('peerType', '') == peerType and activePeers.get(key, {}).get('connectionStatus', '') == 'connected':
                    filteredConnectedPeers.append(activePeers.get(key, {}))
            
            return filteredConnectedPeers

        except Exception as e:
            return []

    def getPeerByHostname(self, hostname: str) -> dict:
        try:
            hostname = hostname.lower()
            activePeers = json.loads(self.redisMessaging.getValue(key="ActiveDiameterPeers").decode())

            for key, value in activePeers.items():
                if activePeers.get(key, {}).get('diameterHostname', '').lower() == hostname and activePeers.get(key, {}).get('connectionStatus', '') == 'connected':
                    return(activePeers.get(key, {}))

        except Exception as e:
            return {}

    def getDiameterMessageType(self, binaryData: str) -> dict:
        """
        Determines whether a message is a request or a response, and the appropriate acronyms for each type.
        """
        packet_vars, avps = self.decode_diameter_packet(binaryData)
        response = {}
        
        for diameterApplication in self.diameterResponseList:
            try:
                assert(packet_vars["command_code"] == diameterApplication["commandCode"])
                assert(packet_vars["ApplicationId"] == diameterApplication["applicationId"])
                if packet_vars["flags_bin"][0:1] == "1":
                    response['inbound'] = diameterApplication["requestAcronym"]
                    response['outbound'] = diameterApplication["responseAcronym"]
                else:
                    response['inbound'] = diameterApplication["responseAcronym"]
                    response['outbound'] = diameterApplication["requestAcronym"]
                self.logTool.log(service='HSS', level='debug', message=f"[diameter.py] Matched message types: {response}", redisClient=self.redisMessaging)
            except Exception as e:
                continue
        return response

    def sendDiameterRequest(self, requestType: str, hostname: str, **kwargs) -> str:
        """
        Sends a given diameter request of requestType to the provided peer hostname, if the peer is connected.
        """
        try:
            request = ''
            requestType = requestType.upper()
            self.logTool.log(service='HSS', level='debug', message=f"[diameter.py] [sendDiameterRequest] [{requestType}] Generating a diameter outbound request", redisClient=self.redisMessaging)
            
            for diameterApplication in self.diameterRequestList:
                try:
                    assert(requestType == diameterApplication["requestAcronym"])
                except Exception as e:
                    continue
                connectedPeer = self.getPeerByHostname(hostname=hostname)
                try:
                    peerIp = connectedPeer['ipAddress']
                    peerPort = connectedPeer['port']
                except Exception as e:
                    return ''
                request = diameterApplication["requestMethod"](**kwargs)
                self.logTool.log(service='HSS', level='debug', message=f"[diameter.py] [sendDiameterRequest] [{requestType}] Successfully generated request: {request}", redisClient=self.redisMessaging)
                outboundQueue = f"diameter-outbound-{peerIp}-{peerPort}"
                sendTime = time.time_ns()
                outboundMessage = json.dumps({"diameter-outbound": request, "inbound-received-timestamp": sendTime})
                self.redisMessaging.sendMessage(queue=outboundQueue, message=outboundMessage, queueExpiry=self.diameterRequestTimeout)
                self.logTool.log(service='HSS', level='debug', message=f"[diameter.py] [sendDiameterRequest] [{requestType}] Queueing for host: {hostname} on {peerIp}-{peerPort}", redisClient=self.redisMessaging)
            return request
        except Exception as e:
            self.logTool.log(service='HSS', level='error', message=f"[diameter.py] [sendDiameterRequest] [{requestType}] Error generating diameter outbound request: {traceback.format_exc()}", redisClient=self.redisMessaging)
            return ''

    def broadcastDiameterRequest(self, requestType: str, peerType: str, **kwargs) -> bool:
        """
        Sends a diameter request of requestType to one or more connected peers, specified by peerType.
        """
        try:
            request = ''
            requestType = requestType.upper()
            self.logTool.log(service='HSS', level='debug', message=f"[diameter.py] [broadcastDiameterRequest] [{requestType}] Broadcasting a diameter outbound request of type: {requestType} to peers of type: {peerType}", redisClient=self.redisMessaging)
            
            for diameterApplication in self.diameterRequestList:
                try:
                    assert(requestType == diameterApplication["requestAcronym"])
                except Exception as e:
                    continue
                connectedPeerList = self.getConnectedPeersByType(peerType=peerType)
                for connectedPeer in connectedPeerList:
                    try:
                        peerIp = connectedPeer['ipAddress']
                        peerPort = connectedPeer['port']
                    except Exception as e:
                        return ''
                    request = diameterApplication["requestMethod"](**kwargs)
                    self.logTool.log(service='HSS', level='debug', message=f"[diameter.py] [broadcastDiameterRequest] [{requestType}] Successfully generated request: {request}", redisClient=self.redisMessaging)
                    outboundQueue = f"diameter-outbound-{peerIp}-{peerPort}"
                    sendTime = time.time_ns()
                    outboundMessage = json.dumps({"diameter-outbound": request, "inbound-received-timestamp": sendTime})
                    self.redisMessaging.sendMessage(queue=outboundQueue, message=outboundMessage, queueExpiry=self.diameterRequestTimeout)
                    self.logTool.log(service='HSS', level='debug', message=f"[diameter.py] [broadcastDiameterRequest] [{requestType}] Queueing for peer type: {peerType} on {peerIp}-{peerPort}", redisClient=self.redisMessaging)
            return connectedPeerList
        except Exception as e:
            return ''

    def awaitDiameterRequestAndResponse(self, requestType: str, hostname: str, timeout: float=0.12, **kwargs) -> str:
        """
        Sends a given diameter request of requestType to the provided peer hostname.
        Ensures the peer is connected, sends the request, then waits on and returns the response.
        If the timeout is reached, the function fails.

        Diameter lacks a unique identifier for all message types, the closest being Session-ID which exists for most.
        We attempt to get the associated response given the following logic:
          - If sessionId is none, attempt to return the first response that matches the expected response method (eg AAA, CEA, etc.) which has a timestamp greater than sendTime.
          - If sessionId is not none, perform the logic above, and also ensure that sessionId matches.

        Returns an empty string if fails.

        Until diameter.py is rewritten to be asynchronous, this method should be called only when strictly necessary. It potentially adds up to 120ms of delay per invocation.
        """
        try:
            request = ''
            requestType = requestType.upper()
            self.logTool.log(service='HSS', level='debug', message=f"[diameter.py] [awaitDiameterRequestAndResponse] [{requestType}] Generating a diameter outbound request", redisClient=self.redisMessaging)
            
            for diameterApplication in self.diameterRequestList:
                try:
                    assert(requestType == diameterApplication["requestAcronym"])
                except Exception as e:
                    continue
                connectedPeer = self.getPeerByHostname(hostname=hostname)
                try:
                    peerIp = connectedPeer['ipAddress']
                    peerPort = connectedPeer['port']
                except Exception as e:
                    return ''
                request = diameterApplication["requestMethod"](**kwargs)
                responseType = diameterApplication["responseAcronym"]
                sessionId = kwargs.get('sessionId', None)
                self.logTool.log(service='HSS', level='debug', message=f"[diameter.py] [awaitDiameterRequestAndResponse] [{requestType}] Successfully generated request: {request}", redisClient=self.redisMessaging)
                sendTime = time.time_ns()
                outboundQueue = f"diameter-outbound-{peerIp}-{peerPort}"
                outboundMessage = json.dumps({"diameter-outbound": request, "inbound-received-timestamp": sendTime})
                self.redisMessaging.sendMessage(queue=outboundQueue, message=outboundMessage, queueExpiry=self.diameterRequestTimeout)
                self.logTool.log(service='HSS', level='debug', message=f"[diameter.py] [awaitDiameterRequestAndResponse] [{requestType}] Queueing for host: {hostname} on {peerIp}-{peerPort}", redisClient=self.redisMessaging)
                startTimer = time.time()
                while True:
                    try:
                        if not time.time() >= startTimer + timeout:
                            if sessionId is None:
                                queuedMessages = self.redisMessaging.getList(key=f"diameter-inbound")
                                self.logTool.log(service='HSS', level='debug', message=f"[diameter.py] [awaitDiameterRequestAndResponse] [{requestType}] queuedMessages(NoSessionId): {queuedMessages}", redisClient=self.redisMessaging)
                                for queuedMessage in queuedMessages:
                                    queuedMessage = json.loads(queuedMessage)
                                    clientAddress = queuedMessage.get('clientAddress', None)
                                    clientPort = queuedMessage.get('clientPort', None)
                                    if clientAddress != peerIp or clientPort != peerPort:
                                        continue
                                    messageReceiveTime = queuedMessage.get('inbound-received-timestamp', None)
                                    if float(messageReceiveTime) > sendTime:
                                        messageHex = queuedMessage.get('diameter-inbound')
                                        messageType = self.getDiameterMessageType(messageHex)
                                        if messageType['inbound'].upper() == responseType.upper():
                                            self.logTool.log(service='HSS', level='debug', message=f"[diameter.py] [awaitDiameterRequestAndResponse] [{requestType}] Found inbound response: {messageHex}", redisClient=self.redisMessaging)
                                            return messageHex
                                time.sleep(0.02)
                            else:
                                queuedMessages = self.redisMessaging.getList(key=f"diameter-inbound")
                                self.logTool.log(service='HSS', level='debug', message=f"[diameter.py] [awaitDiameterRequestAndResponse] [{requestType}] queuedMessages({sessionId}): {queuedMessages} responseType: {responseType}", redisClient=self.redisMessaging)
                                for queuedMessage in queuedMessages:
                                    queuedMessage = json.loads(queuedMessage)
                                    clientAddress = queuedMessage.get('clientAddress', None)
                                    clientPort = queuedMessage.get('clientPort', None)
                                    if clientAddress != peerIp or clientPort != peerPort:
                                        continue
                                    messageReceiveTime = queuedMessage.get('inbound-received-timestamp', None)
                                    if float(messageReceiveTime) > sendTime:
                                        messageHex = queuedMessage.get('diameter-inbound')
                                        messageType = self.getDiameterMessageType(messageHex)
                                        if messageType['inbound'].upper() == responseType.upper():
                                            packetVars, avps = self.decode_diameter_packet(messageHex)
                                            messageSessionId = bytes.fromhex(self.get_avp_data(avps, 263)[0]).decode('ascii')
                                            if messageSessionId == sessionId:
                                                self.logTool.log(service='HSS', level='debug', message=f"[diameter.py] [awaitDiameterRequestAndResponse] [{requestType}] Matched on Session Id: {sessionId}", redisClient=self.redisMessaging)
                                                return messageHex
                                time.sleep(0.02)
                        else:
                            return ''
                    except Exception as e:
                        self.logTool.log(service='HSS', level='debug', message=f"[diameter.py] [awaitDiameterRequestAndResponse] [{requestType}] Traceback: {traceback.format_exc()}", redisClient=self.redisMessaging)
                        return ''
        except Exception as e:
            self.logTool.log(service='HSS', level='error', message=f"[diameter.py] [awaitDiameterRequestAndResponse] [{requestType}] Error generating diameter outbound request: {traceback.format_exc()}", redisClient=self.redisMessaging)
            return ''

    def generateDiameterResponse(self, binaryData: str) -> str:
            try:
                packet_vars, avps = self.decode_diameter_packet(binaryData)
                origin_host = self.get_avp_data(avps, 264)[0]
                origin_host = binascii.unhexlify(origin_host).decode("utf-8")
                response = ''

                self.logTool.log(service='HSS', level='debug', message=f"[diameter.py] [generateDiameterResponse] Generating a diameter response", redisClient=self.redisMessaging)

                # Drop packet if it's a response packet:
                if packet_vars["flags_bin"][0:1] == "0":
                    self.logTool.log(service='HSS', level='debug', message="[diameter.py] [generateDiameterResponse] Got a Response, not a request - dropping it.", redisClient=self.redisMessaging)
                    self.logTool.log(service='HSS', level='debug', message=packet_vars, redisClient=self.redisMessaging)
                    return
                
                for diameterApplication in self.diameterResponseList:
                    try:
                        assert(packet_vars["command_code"] == diameterApplication["commandCode"])
                        assert(packet_vars["ApplicationId"] == diameterApplication["applicationId"])
                        if 'flags' in diameterApplication:
                            assert(str(packet_vars["flags"]) == str(diameterApplication["flags"]))
                        self.logTool.log(service='HSS', level='debug', message=f"[diameter.py] [generateDiameterResponse] [{diameterApplication.get('requestAcronym', '')}] Attempting to generate response", redisClient=self.redisMessaging)
                        response = diameterApplication["responseMethod"](packet_vars, avps)
                        self.logTool.log(service='HSS', level='debug', message=f"[diameter.py] [generateDiameterResponse] [{diameterApplication.get('requestAcronym', '')}] Successfully generated response: {response}", redisClient=self.redisMessaging)
                        break
                    except Exception as e:
                        continue

                self.redisMessaging.sendMetric(serviceName='diameter', metricName='prom_diam_response_count_successful',
                                    metricType='counter', metricAction='inc', 
                                    metricValue=1.0, metricHelp='Number of Successful Diameter Responses',
                                    metricExpiry=60)
                return response
            except Exception as e:
                self.redisMessaging.sendMetric(serviceName='diameter', metricName='prom_diam_response_count_fail',
                                                metricType='counter', metricAction='inc', 
                                                metricValue=1.0, metricHelp='Number of Failed Diameter Responses',
                                                metricExpiry=60)
                return ''

    def generateDiameterRequest(self, requestType: str, **kwargs) -> str:
        """
        Returns a given diameter request of requestType in a hex string.
        """
        try:
            request = ''
            requestType = requestType.upper()
            self.logTool.log(service='AS', level='debug', message=f"[diameter.py] [generateDiameterRequest] [{requestType}] Generating a diameter outbound request", redisClient=self.redisMessaging)
            
            for diameterApplication in self.diameterRequestList:
                try:
                    assert(requestType == diameterApplication["requestAcronym"])
                except Exception as e:
                    continue

                request = diameterApplication["requestMethod"](**kwargs)
                self.logTool.log(service='AS', level='debug', message=f"[diameter.py] [generateDiameterRequest] [{requestType}] Successfully generated request: {request}", redisClient=self.redisMessaging)
                return request
        except Exception as e:
            self.logTool.log(service='AS', level='error', message=f"[diameter.py] [generateDiameterRequest] [{requestType}] Error generating diameter outbound request: {traceback.format_exc()}", redisClient=self.redisMessaging)
            return ''

    def AVP_278_Origin_State_Incriment(self, avps):                                               #Capabilities Exchange Answer incriment AVP body
        for avp_dicts in avps:
            if avp_dicts['avp_code'] == 278:
                origin_state_incriment_int = int(avp_dicts['misc_data'], 16)
                origin_state_incriment_int = origin_state_incriment_int + 1
                origin_state_incriment_hex = format(origin_state_incriment_int,"x").zfill(8)
                return origin_state_incriment_hex

    def Charging_Rule_Generator(self, ChargingRules=None, ue_ip=None, chargingRuleName=None, action="install"):
        if action not in ['install', 'remove']:
            return None
        
        if action == 'remove':
            if chargingRuleName is None:
                return None
            Charging_Rule_Name = self.generate_vendor_avp(1005, "c0", 10415, str(binascii.hexlify(str.encode(str(chargingRuleName))),'ascii'))
            ChargingRuleDef = Charging_Rule_Name
            return self.generate_vendor_avp(1002, "c0", 10415, ChargingRuleDef)
        
        else:
            if ChargingRules is None or ue_ip is None:
                return None

            #Install Charging Rules
            Charging_Rule_Name = self.generate_vendor_avp(1005, "c0", 10415, str(binascii.hexlify(str.encode(str(ChargingRules['rule_name']))),'ascii'))

            #Populate all Flow Information AVPs
            Flow_Information = ''
            for tft in ChargingRules['tft']:
                #If {{ UE_IP }} in TFT splice in the real UE IP Value
                try:
                    tft['tft_string'] = tft['tft_string'].replace('{{ UE_IP }}', str(ue_ip))
                    tft['tft_string'] = tft['tft_string'].replace('{{UE_IP}}', str(ue_ip))
                except Exception as E:
                    self.logTool.log(service='HSS', level='error', message="Failed to splice in UE IP into flow description", redisClient=self.redisMessaging)
                
                #Valid Values for Flow_Direction: 0- Unspecified, 1 - Downlink, 2 - Uplink, 3 - Bidirectional
                Flow_Direction = self.generate_vendor_avp(1080, "80", 10415, self.int_to_hex(tft['direction'], 4))
                Flow_Description = self.generate_vendor_avp(507, "c0", 10415, str(binascii.hexlify(str.encode(tft['tft_string'])),'ascii'))
                Flow_Information += self.generate_vendor_avp(1058, "80", 10415, Flow_Direction + Flow_Description)

            Flow_Status = self.generate_vendor_avp(511, "c0", 10415, self.int_to_hex(2, 4))

            #QCI 
            QCI = self.generate_vendor_avp(1028, "c0", 10415, self.int_to_hex(ChargingRules['qci'], 4))

            #ARP
            AVP_Priority_Level = self.generate_vendor_avp(1046, "80", 10415, self.int_to_hex(int(ChargingRules['arp_priority']), 4))
            AVP_Preemption_Capability = self.generate_vendor_avp(1047, "80", 10415, self.int_to_hex(int(not ChargingRules['arp_preemption_capability']), 4))
            AVP_Preemption_Vulnerability = self.generate_vendor_avp(1048, "80", 10415, self.int_to_hex(int(not ChargingRules['arp_preemption_vulnerability']), 4))
            ARP = self.generate_vendor_avp(1034, "80", 10415, AVP_Priority_Level + AVP_Preemption_Capability + AVP_Preemption_Vulnerability)

            #Max Requested Bandwidth
            Bandwidth_info = ''
            Bandwidth_info += self.generate_vendor_avp(516, "c0", 10415, self.int_to_hex(int(ChargingRules['mbr_ul']), 4))
            Bandwidth_info += self.generate_vendor_avp(515, "c0", 10415, self.int_to_hex(int(ChargingRules['mbr_dl']), 4))

            #GBR
            if int(ChargingRules['gbr_ul']) != 0:
                Bandwidth_info += self.generate_vendor_avp(1026, "c0", 10415, self.int_to_hex(int(ChargingRules['gbr_ul']), 4))
            if int(ChargingRules['gbr_dl']) != 0:                
                Bandwidth_info += self.generate_vendor_avp(1025, "c0", 10415, self.int_to_hex(int(ChargingRules['gbr_dl']), 4))

            #Populate QoS Information
            QoS_Information = self.generate_vendor_avp(1016, "c0", 10415, QCI + ARP + Bandwidth_info)
            
            #Precedence
            Precedence = self.generate_vendor_avp(1010, "c0", 10415, self.int_to_hex(ChargingRules['precedence'], 4))

            #Rating Group
            if ChargingRules['rating_group'] != None:
                RatingGroup = self.generate_avp(432, 40, format(int(ChargingRules['rating_group']),"x").zfill(8))                   #Rating-Group-ID
            else:
                RatingGroup = ''
            

            #Complete Charging Rule Defintion
            ChargingRuleDef = Charging_Rule_Name + Flow_Information + Flow_Status + QoS_Information + Precedence + RatingGroup
            ChargingRuleDef = self.generate_vendor_avp(1003, "c0", 10415, ChargingRuleDef)

            #Charging Rule Install
            return self.generate_vendor_avp(1001, "c0", 10415, ChargingRuleDef)
    
    #### Diameter Answers ####

    #Capabilities Exchange Answer
    def Answer_257(self, packet_vars, avps):
        avp = ''                                                                                    #Initiate empty var AVP 
        avp += self.generate_avp(268, 40, self.int_to_hex(2001, 4))                                 #Result Code (DIAMETER_SUCCESS (2001))
        avp += self.generate_avp(264, 40, self.OriginHost)                                          #Origin Host
        avp += self.generate_avp(296, 40, self.OriginRealm)                                         #Origin Realm
        for avps_to_check in avps:                                                                  #Only include AVP 278 (Origin State) if inital request included it
            if avps_to_check['avp_code'] == 278:
                avp += self.generate_avp(278, 40, self.AVP_278_Origin_State_Incriment(avps))        #Origin State (Has to be incrimented (Handled by AVP_278_Origin_State_Incriment))
        for host in self.config['hss']['bind_ip']:                                                  #Loop through all IPs from Config and add to response
            avp += self.generate_avp(257, 40, self.ip_to_hex(host))                                 #Host-IP-Address (For this to work on Linux this is the IP defined in the hostsfile for localhost)
        avp += self.generate_avp(266, 40, "00000000")                                               #Vendor-Id
        avp += self.generate_avp(269, "00", self.ProductName)                                       #Product-Name

        avp += self.generate_avp(267, 40, "000027d9")                                               #Firmware-Revision
        avp += self.generate_avp(265, 40, format(int(10415),"x").zfill(8))                               #Supported-Vendor-ID (3GPP)
        avp += self.generate_avp(260, 40, "000001024000000c" + format(int(16777251),"x").zfill(8) +  "0000010a4000000c000028af")      #Vendor-Specific-Application-ID (S6a)
        avp += self.generate_avp(265, 40, format(int(10415),"x").zfill(8))                               #Supported-Vendor-ID (3GPP)        
        avp += self.generate_avp(260, 40, "000001024000000c" + format(int(16777216),"x").zfill(8) +  "0000010a4000000c000028af")      #Vendor-Specific-Application-ID (Cx)
        avp += self.generate_avp(265, 40, format(int(10415),"x").zfill(8))                               #Supported-Vendor-ID (3GPP)        
        avp += self.generate_avp(260, 40, "000001024000000c" + format(int(16777252),"x").zfill(8) +  "0000010a4000000c000028af")      #Vendor-Specific-Application-ID (S13)
        avp += self.generate_avp(265, 40, format(int(10415),"x").zfill(8))                               #Supported-Vendor-ID (3GPP)        
        avp += self.generate_avp(260, 40, "000001024000000c" + format(int(16777291),"x").zfill(8) +  "0000010a4000000c000028af")      #Vendor-Specific-Application-ID (SLh)
        avp += self.generate_avp(265, 40, format(int(10415),"x").zfill(8))                               #Supported-Vendor-ID (3GPP)
        avp += self.generate_avp(260, 40, "000001024000000c" + format(int(16777217),"x").zfill(8) +  "0000010a4000000c000028af")      #Vendor-Specific-Application-ID (Sh)       
        avp += self.generate_avp(265, 40, format(int(10415),"x").zfill(8))                               #Supported-Vendor-ID (3GPP)
        avp += self.generate_avp(260, 40, "000001024000000c" + format(int(16777236),"x").zfill(8) +  "0000010a4000000c000028af")      #Vendor-Specific-Application-ID (Rx)
        avp += self.generate_avp(265, 40, format(int(10415),"x").zfill(8))                               #Supported-Vendor-ID (3GPP)
        avp += self.generate_avp(260, 40, "000001024000000c" + format(int(16777238),"x").zfill(8) +  "0000010a4000000c000028af")      #Vendor-Specific-Application-ID (Gx)
        avp += self.generate_avp(258, 40, format(int(16777238),"x").zfill(8))                            #Auth-Application-ID - Diameter Gx
        avp += self.generate_avp(258, 40, format(int(10),"x").zfill(8))                                  #Auth-Application-ID - Diameter CER
        avp += self.generate_avp(265, 40, format(int(5535),"x").zfill(8))                                #Supported-Vendor-ID (3GGP v2)
        avp += self.generate_avp(265, 40, format(int(10415),"x").zfill(8))                               #Supported-Vendor-ID (3GPP)
        avp += self.generate_avp(265, 40, format(int(13019),"x").zfill(8))                               #Supported-Vendor-ID 13019 (ETSI)

        response = self.generate_diameter_packet("01", "00", 257, 0, packet_vars['hop-by-hop-identifier'], packet_vars['end-to-end-identifier'], avp)            #Generate Diameter packet       
        # self.logTool.log(service='HSS', level='debug', message="Successfully Generated CEA", redisClient=self.redisMessaging)
        return response

    #Device Watchdog Answer                                                 
    def Answer_280(self, packet_vars, avps): 
        
        avp = ''                                                                                    #Initiate empty var AVP 
        avp += self.generate_avp(268, 40, self.int_to_hex(2001, 4))                                           #Result Code (DIAMETER_SUCCESS (2001))
        avp += self.generate_avp(264, 40, self.OriginHost)                                                    #Origin Host
        avp += self.generate_avp(296, 40, self.OriginRealm)                                                   #Origin Realm
        for avps_to_check in avps:                                                                  #Only include AVP 278 (Origin State) if inital request included it
            if avps_to_check['avp_code'] == 278:                                
                avp += self.generate_avp(278, 40, self.AVP_278_Origin_State_Incriment(avps))                  #Origin State (Has to be incrimented (Handled by AVP_278_Origin_State_Incriment))
        response = self.generate_diameter_packet("01", "00", 280, 0, packet_vars['hop-by-hop-identifier'], packet_vars['end-to-end-identifier'], avp)            #Generate Diameter packet      
        # self.logTool.log(service='HSS', level='debug', message="Successfully Generated DWA", redisClient=self.redisMessaging)
        orignHost = self.get_avp_data(avps, 264)[0]                         #Get OriginHost from AVP
        orignHost = binascii.unhexlify(orignHost).decode('utf-8')           #Format it
        return response

    # 3GPP Gx Credit Control Answer
    def Answer_16777238_272(self, packet_vars, avps):
        try:
            CC_Request_Type = self.get_avp_data(avps, 416)[0]
            CC_Request_Number = self.get_avp_data(avps, 415)[0]
            #Called Station ID
            # self.logTool.log(service='HSS', level='debug', message="[diameter.py] [Answer_16777238_272] [CCA] Attempting to find APN in CCR", redisClient=self.redisMessaging)
            apn = bytes.fromhex(self.get_avp_data(avps, 30)[0]).decode('utf-8')
            # Strip plmn based domain from apn, if present
            try:
                if '.' in apn:
                        assert('mcc' in apn)
                        assert('mnc' in apn)
                        apn = apn.split('.')[0]
            except Exception as e:
                apn = bytes.fromhex(self.get_avp_data(avps, 30)[0]).decode('utf-8')
            # self.logTool.log(service='HSS', level='debug', message="[diameter.py] [Answer_16777238_272] [CCA] CCR for APN " + str(apn), redisClient=self.redisMessaging)
            OriginHost = self.get_avp_data(avps, 264)[0]                          #Get OriginHost from AVP
            OriginHost = binascii.unhexlify(OriginHost).decode('utf-8')      #Format it

            OriginRealm = self.get_avp_data(avps, 296)[0]                          #Get OriginRealm from AVP
            OriginRealm = binascii.unhexlify(OriginRealm).decode('utf-8')      #Format it

            try:        #Check if we have a record-route set as that's where we'll need to send the response
                remote_peer = self.get_avp_data(avps, 282)[-1]                          #Get first record-route header
                remote_peer = binascii.unhexlify(remote_peer).decode('utf-8')           #Format it
            except:     #If we don't have a record-route set, we'll send the response to the OriginHost
                remote_peer = OriginHost
            # self.logTool.log(service='HSS', level='debug', message="[diameter.py] [Answer_16777238_272] [CCA] Remote Peer is " + str(remote_peer), redisClient=self.redisMessaging)
            remote_peer = remote_peer + ";" + str(self.config['hss']['OriginHost'])

            avp = ''                                                                                    #Initiate empty var AVP
            session_id = self.get_avp_data(avps, 263)[0]                                                     #Get Session-ID
            # self.logTool.log(service='HSS', level='debug', message="[diameter.py] [Answer_16777238_272] [CCA] Session Id is " + str(binascii.unhexlify(session_id).decode()), redisClient=self.redisMessaging)
            avp += self.generate_avp(263, 40, session_id)                                                    #Session-ID AVP set
            avp += self.generate_avp(258, 40, "01000016")                                                    #Auth-Application-Id (3GPP Gx 16777238)
            avp += self.generate_avp(416, 40, format(int(CC_Request_Type),"x").zfill(8))                     #CC-Request-Type
            avp += self.generate_avp(415, 40, format(int(CC_Request_Number),"x").zfill(8))                   #CC-Request-Number
            #Get Subscriber info from Subscription ID
            for SubscriptionIdentifier in self.get_avp_data(avps, 443):
                for UniqueSubscriptionIdentifier in SubscriptionIdentifier:
                    if UniqueSubscriptionIdentifier['avp_code'] == 444:
                        imsi = binascii.unhexlify(UniqueSubscriptionIdentifier['misc_data']).decode('utf-8')

            ChargingRules = get_static_charging_rules()
            # CCR - Initial Request
            if int(CC_Request_Type) == 1:
                # self.logTool.log(service='HSS', level='debug', message="[diameter.py] [Answer_16777238_272] [CCA] Request type for CCA is 1 - Initial", redisClient=self.redisMessaging)

                #Get UE IP            
                try:
                    ue_ip = self.get_avp_data(avps, 8)[0]
                    ue_ip = str(self.hex_to_ip(ue_ip))
                except Exception as E:
                    ue_ip = 'Failed to Decode / Get UE IP'

                #Store PGW location into Database
                remote_peer = remote_peer + ";" + str(self.config['hss']['OriginHost'])
                
                #Supported-Features(628) (Gx feature list)
                avp += self.generate_vendor_avp(628, "80", 10415, "0000010a4000000c000028af0000027580000010000028af000000010000027680000010000028af0000000b")

                #Default EPS Bearer QoS (From database with fallback source CCR-I, then omission)
                try:
                    apn_data = ChargingRules['apn_data']
                    #AMBR
                    AMBR = ''                                                                                   #Initiate empty var AVP for AMBR
                    apn_ambr_ul = int(apn_data['apn_ambr_ul'])
                    apn_ambr_dl = int(apn_data['apn_ambr_dl'])
                    AMBR += self.generate_vendor_avp(516, "c0", 10415, self.int_to_hex(apn_ambr_ul, 4))                    #Max-Requested-Bandwidth-UL
                    AMBR += self.generate_vendor_avp(515, "c0", 10415, self.int_to_hex(apn_ambr_dl, 4))                    #Max-Requested-Bandwidth-DL
                    APN_AMBR = self.generate_vendor_avp(1435, "c0", 10415, AMBR)

                    #AVP: Allocation-Retention-Priority(1034) l=60 f=V-- vnd=TGPP
                    # Per TS 29.212, we need to flip our stored values for capability and vulnerability:
                    # PRE-EMPTION_CAPABILITY_ENABLED (0)
                    # PRE-EMPTION_CAPABILITY_DISABLED (1)
                    # PRE-EMPTION_VULNERABILITY_ENABLED (0)
                    # PRE-EMPTION_VULNERABILITY_DISABLED (1)
                    AVP_Priority_Level = self.generate_vendor_avp(1046, "80", 10415, self.int_to_hex(int(apn_data['arp_priority']), 4))
                    AVP_Preemption_Capability = self.generate_vendor_avp(1047, "80", 10415, self.int_to_hex(int(not apn_data['arp_preemption_capability']), 4))
                    AVP_Preemption_Vulnerability = self.generate_vendor_avp(1048, "80", 10415, self.int_to_hex(int(not apn_data['arp_preemption_vulnerability']), 4))
                    AVP_ARP = self.generate_vendor_avp(1034, "80", 10415, AVP_Priority_Level + AVP_Preemption_Capability + AVP_Preemption_Vulnerability)
                    AVP_QoS = self.generate_vendor_avp(1028, "c0", 10415, self.int_to_hex(int(apn_data['qci']), 4))
                    avp += self.generate_vendor_avp(1049, "80", 10415, AVP_QoS + AVP_ARP)
                except Exception as E:
                    default_EPS_QoS = self.get_avp_data(avps, 1049)[0][8:]
                    if len(default_EPS_QoS) > 0:
                        avp += self.generate_vendor_avp(1049, "80", 10415, default_EPS_QoS)

                #QoS-Information
                try:
                    apn_data = ChargingRules['apn_data']
                    apn_ambr_ul = int(apn_data['apn_ambr_ul'])
                    apn_ambr_dl = int(apn_data['apn_ambr_dl'])
                    QoS_Information = self.generate_vendor_avp(1041, "80", 10415, self.int_to_hex(apn_ambr_ul, 4))                                                                  
                    QoS_Information += self.generate_vendor_avp(1040, "80", 10415, self.int_to_hex(apn_ambr_dl, 4))
                    avp += self.generate_vendor_avp(1016, "80", 10415, QoS_Information)
                except Exception as E: 
                    QoS_Information = ''
                    for AMBR_Part in self.get_avp_data(avps, 1016)[0]:

                        AMBR_AVP = self.generate_vendor_avp(AMBR_Part['avp_code'], "80", 10415, AMBR_Part['misc_data'][8:])
                        QoS_Information += AMBR_AVP

                    avp += self.generate_vendor_avp(1016, "80", 10415, QoS_Information)
                
                # If database returned an existing ChargingRule defintion add ChargingRule to CCA-I
                # If a Charging Rule Install AVP is present, it may trigger the creation of a dedicated bearer.
                if ChargingRules and ChargingRules['charging_rules'] is not None:
                    try:
                        for individual_charging_rule in ChargingRules['charging_rules']:
                            chargingRule = self.Charging_Rule_Generator(ChargingRules=individual_charging_rule, ue_ip=ue_ip)
                            if len(chargingRule) > 0:
                                avp += chargingRule

                    except Exception as E:
                        pass
                        # print("Hello")
                        # self.logTool.log(service='HSS', level='debug', message="[diameter.py] [Answer_16777238_272] [CCA] Error in populating dynamic charging rules: " + str(E), redisClient=self.redisMessaging)

            # CCR - Termination Request
            # elif int(CC_Request_Type) == 3:
            #     # self.logTool.log(service='HSS', level='debug', message="[diameter.py] [Answer_16777238_272] [CCA] Request type for CCA is 3 - Termination", redisClient=self.redisMessaging)
            #     if 'ims' in apn:
            #             try:
            #                 self.database.Update_Serving_CSCF(imsi=imsi, serving_cscf=None)
            #                 self.database.Update_Proxy_CSCF(imsi=imsi, proxy_cscf=None)
            #                 self.database.Update_Serving_APN(imsi=imsi, apn=apn, pcrf_session_id=str(binascii.unhexlify(session_id).decode()), serving_pgw=OriginHost, subscriber_routing='')
            #                 self.logTool.log(service='HSS', level='debug', message=f"[diameter.py] [Answer_16777238_272] [CCA] Successfully cleared stored IMS state", redisClient=self.redisMessaging)
            #             except Exception as e:
            #                 print(e)
            #                 # self.logTool.log(service='HSS', level='debug', message=f"[diameter.py] [Answer_16777238_272] [CCA] Failed to clear stored IMS state: {traceback.format_exc()}", redisClient=self.redisMessaging)
            #     else:
            #             try:
            #                 self.database.Update_Serving_APN(imsi=imsi, apn=apn, pcrf_session_id=str(binascii.unhexlify(session_id).decode()), serving_pgw=OriginHost, subscriber_routing='')
            #                 # self.logTool.log(service='HSS', level='debug', message=f"[diameter.py] [Answer_16777238_272] [CCA] Successfully cleared stored state for: {apn}", redisClient=self.redisMessaging)
            #             except Exception as e:
            #                 print(e)
            #                 # self.logTool.log(service='HSS', level='debug', message=f"[diameter.py] [Answer_16777238_272] [CCA] Failed to clear apn state for {apn}: {traceback.format_exc()}", redisClient=self.redisMessaging)

            avp += self.generate_avp(264, 40, self.OriginHost)                                                    #Origin Host
            avp += self.generate_avp(296, 40, self.OriginRealm)                                                   #Origin Realm
            avp += self.generate_avp(268, 40, self.int_to_hex(2001, 4))                                           #Result Code (DIAMETER_SUCCESS (2001))
            response = self.generate_diameter_packet("01", "40", 272, 16777238, packet_vars['hop-by-hop-identifier'], packet_vars['end-to-end-identifier'], avp)     #Generate Diameter packet
            # return response
        except Exception as e:                                             #Get subscriber details
            #Handle if the subscriber is not present in HSS return "DIAMETER_ERROR_USER_UNKNOWN"
            self.redisMessaging.sendMetric(serviceName='diameter', metricName='prom_diam_auth_event_count',
                                            metricType='counter', metricAction='inc', 
                                            metricValue=1.0, 
                                            metricLabels={
                                                        "diameter_application_id": 16777238,
                                                        "diameter_cmd_code": 272,
                                                        "event": "Unknown User",
                                                        "imsi_prefix": str(imsi[0:6])},
                                            metricHelp='Diameter Authentication related Counters',
                                            metricExpiry=60)
            avp += self.generate_avp(264, 40, self.OriginHost)                                                    #Origin Host
            avp += self.generate_avp(296, 40, self.OriginRealm)                                                   #Origin Realm
            avp += self.generate_avp(268, 40, self.int_to_hex(5030, 4))                                           #Result Code (DIAMETER ERROR - User Unknown)
            response = self.generate_diameter_packet("01", "40", 272, 16777238, packet_vars['hop-by-hop-identifier'], packet_vars['end-to-end-identifier'], avp)     #Generate Diameter packet
        return response

    #Generate a Generic error handler with Result Code as input
    def Respond_ResultCode(self, packet_vars, avps, result_code):
        self.logTool.log(service='HSS', level='error', message="Responding with result code " + str(result_code) + " to request with command code " + str(packet_vars['command_code']), redisClient=self.redisMessaging)
        avp = ''                                                                                    #Initiate empty var AVP
        avp += self.generate_avp(264, 40, self.OriginHost)                                                    #Origin Host
        avp += self.generate_avp(296, 40, self.OriginRealm)                                                   #Origin Realm
        try:
            session_id = self.get_avp_data(avps, 263)[0]                                                     #Get Session-ID
            avp += self.generate_avp(263, 40, session_id)                                                    #Set session ID to received session ID
        except:
            self.logTool.log(service='HSS', level='debug', message="Failed to add SessionID into error", redisClient=self.redisMessaging)
        for avps_to_check in avps:                                                                  #Only include AVP 260 (Vendor-Specific-Application-ID) if inital request included it
            if avps_to_check['avp_code'] == 260:
                concat_subavp = ''
                for sub_avp in avps_to_check['misc_data']:
                    concat_subavp += self.generate_avp(sub_avp['avp_code'], sub_avp['avp_flags'], sub_avp['misc_data'])
                avp += self.generate_avp(260, 40, concat_subavp)        #Vendor-Specific-Application-ID
        avp += self.generate_avp(268, 40, self.int_to_hex(result_code, 4))                                                   #Response Code
        
        #Experimental Result AVP(Response Code for Failure)
        avp_experimental_result = ''
        avp_experimental_result += self.generate_vendor_avp(266, 40, 10415, '')                         #AVP Vendor ID
        avp_experimental_result += self.generate_avp(298, 40, self.int_to_hex(result_code, 4))                 #AVP Experimental-Result-Code: DIAMETER_ERROR_USER_UNKNOWN (5001)
        avp += self.generate_avp(297, 40, avp_experimental_result)                                      #AVP Experimental-Result(297)

        response = self.generate_diameter_packet("01", "60", int(packet_vars['command_code']), int(packet_vars['ApplicationId']), packet_vars['hop-by-hop-identifier'], packet_vars['end-to-end-identifier'], avp)     #Generate Diameter packet
        return response

 #### Diameter Requests ####

    #Capabilities Exchange Request
    def Request_257(self):
        avp = ''
        avp += self.generate_avp(264, 40, self.OriginHost)                                                    #Origin Host
        avp += self.generate_avp(296, 40, self.OriginRealm)                                                   #Origin Realm
        avp += self.generate_avp(257, 40, self.ip_to_hex(socket.gethostbyname(socket.gethostname())))         #Host-IP-Address (For this to work on Linux this is the IP defined in the hostsfile for localhost)
        avp += self.generate_avp(266, 40, "00000000")                                                    #Vendor-Id
        avp += self.generate_avp(269, "00", self.ProductName)                                                   #Product-Name
        avp += self.generate_avp(260, 40, "000001024000000c01000023" +  "0000010a4000000c000028af")      #Vendor-Specific-Application-ID (S6a)
        avp += self.generate_avp(260, 40, "000001024000000c01000016" +  "0000010a4000000c000028af")      #Vendor-Specific-Application-ID (Gx)
        avp += self.generate_avp(260, 40, "000001024000000c01000027" +  "0000010a4000000c000028af")      #Vendor-Specific-Application-ID (SLg)
        avp += self.generate_avp(260, 40, "000001024000000c" + format(int(16777217),"x").zfill(8) +  "0000010a4000000c000028af")      #Vendor-Specific-Application-ID (Sh)
        avp += self.generate_avp(260, 40, "000001024000000c" + format(int(16777216),"x").zfill(8) +  "0000010a4000000c000028af")      #Vendor-Specific-Application-ID (Cx)
        avp += self.generate_avp(258, 40, format(int(4294967295),"x").zfill(8))                          #Auth-Application-ID Relay
        avp += self.generate_avp(265, 40, format(int(5535),"x").zfill(8))                               #Supported-Vendor-ID (3GGP v2)
        avp += self.generate_avp(258, 40, format(int(16777272),"x").zfill(8))                           #Supported-Vendor-ID (S6b) 
        avp += self.generate_avp(265, 40, format(int(10415),"x").zfill(8))                               #Supported-Vendor-ID (3GPP)
        avp += self.generate_avp(265, 40, format(int(13019),"x").zfill(8))                               #Supported-Vendor-ID 13019 (ETSI)
        response = self.generate_diameter_packet("01", "80", 257, 0, self.generate_id(4), self.generate_id(4), avp)            #Generate Diameter packet
        return response

    #Device Watchdog Request
    def Request_280(self):
        avp = ''
        avp += self.generate_avp(264, 40, self.OriginHost)                                                    #Origin Host
        avp += self.generate_avp(296, 40, self.OriginRealm)                                                   #Origin Realm
        response = self.generate_diameter_packet("01", "80", 280, 0, self.generate_id(4), self.generate_id(4), avp)#Generate Diameter packet
        return response

        #3GPP Gx - Credit Control Request
    def Request_16777238_272(self, imsi, apn, ccr_type, destinationHost, destinationRealm, sessionId=None):
        avp = ''
        if sessionId == None:
            sessionid = 'nickpc.localdomain;' + self.generate_id(5) + ';1;app_gx'                           #Session state generate
        else:
            sessionid = sessionId
        avp += self.generate_avp(263, 40, str(binascii.hexlify(str.encode(sessionid)),'ascii'))          #Session State set AVP
        #AVP: Vendor-Specific-Application-Id(260) l=32 f=-M-
        VendorSpecificApplicationId = ''
        VendorSpecificApplicationId += self.generate_vendor_avp(266, 40, 10415, '')                     #AVP Vendor ID
        VendorSpecificApplicationId += self.generate_avp(258, 40, format(int(16777238),"x").zfill(8))   #Auth-Application-ID Gx
        avp += self.generate_avp(260, 40, VendorSpecificApplicationId)   
        avp += self.generate_avp(277, 40, "00000001")                                                    #Auth-Session-State (Not maintained)        
        avp += self.generate_avp(264, 40, self.OriginHost)                                               #Origin Host
        avp += self.generate_avp(296, 40, self.OriginRealm)                                              #Origin Realm
        
        avp += self.generate_avp(258, 40, format(int(16777238),"x").zfill(8))   #Auth-Application-ID Gx

        #CCR Type
        avp += self.generate_avp(416, 40, format(int(ccr_type),"x").zfill(8))
        avp += self.generate_avp(415, 40, format(int(0),"x").zfill(8))

        #Subscription ID
        Subscription_ID_Data = self.generate_avp(444, 40, str(binascii.hexlify(str.encode(imsi)),'ascii'))
        Subscription_ID_Type = self.generate_avp(450, 40, format(int(1),"x").zfill(8))
        avp += self.generate_avp(443, 40, Subscription_ID_Type + Subscription_ID_Data)


        #AVP: Supported-Features(628) l=36 f=V-- vnd=TGPP
        SupportedFeatures = ''
        SupportedFeatures += self.generate_vendor_avp(266, 40, 10415, '')                     #AVP Vendor ID
        SupportedFeatures += self.generate_vendor_avp(629, 80, 10415, self.int_to_hex(1, 4))  #Feature-List ID
        SupportedFeatures += self.generate_vendor_avp(630, 80, 10415, "0000000b")             #Feature-List Flags
        avp += self.generate_vendor_avp(628, "80", 10415, SupportedFeatures)                  #Supported-Features(628) l=36 f=V-- vnd=TGPP

        avp += self.generate_vendor_avp(1024, 80, 10415, self.int_to_hex(1, 4))                 #Network Requests Supported
        
        avp += self.generate_avp(8, 40, binascii.b2a_hex(os.urandom(4)).decode('utf-8'))        #Framed IP Address Randomly Generated

        avp += self.generate_vendor_avp(1027, 'c0', 10415, self.int_to_hex(5, 4))                 #IP CAN Type (EPS)
        avp += self.generate_vendor_avp(1032, 'c0', 10415, self.int_to_hex(1004, 4))              #RAT-Type (EUTRAN)
        #Default EPS Bearer QoS
        avp += self.generate_vendor_avp(1049, 80, 10415, 
            '0000041980000058000028af00000404c0000010000028af000000090000040a8000003c000028af0000041680000010000028af000000080000041780000010000028af000000010000041880000010000028af00000001')
        #3GPP-User-Location-Information
        avp += self.generate_vendor_avp(22, 80, 10415, 
            '8205f539007b05f53900000001')
        avp += self.generate_vendor_avp(23, 80, 10415, '00000000')                              #MS Timezone

        #Called Station ID (APN)
        avp += self.generate_avp(30, 40, str(binascii.hexlify(str.encode(apn)),'ascii'))

        response = self.generate_diameter_packet("01", "c0", 272, 16777238, self.generate_id(4), self.generate_id(4), avp)     #Generate Diameter packet
        return response

    #3GPP Gx - Re Auth Request
    def Request_16777238_258(self, sessionId, servingPgw, servingRealm, chargingRules=None, ueIp=None, chargingRuleAction='install', chargingRuleName=None):
        avp = ''
        avp += self.generate_avp(263, 40, str(binascii.hexlify(str.encode(sessionId)),'ascii'))          #Session-Id set AVP

        #Setup Charging Rule
        if chargingRules is not None and ueIp is not None:
            avp += self.Charging_Rule_Generator(ChargingRules=chargingRules, ue_ip=ueIp)
        elif chargingRuleName is not None and chargingRuleAction == 'remove':
            avp += self.Charging_Rule_Generator(action=chargingRuleAction, chargingRuleName=chargingRuleName)

        avp += self.generate_avp(264, 40, self.OriginHost)                                               #Origin Host
        avp += self.generate_avp(296, 40, self.OriginRealm)                                              #Origin Realm
        avp += self.generate_avp(293, 40, self.string_to_hex(servingPgw))                                               #Destination Host
        avp += self.generate_avp(283, 40, self.string_to_hex(servingRealm))                                               #Destination Realm
        avp += self.generate_avp(258, 40, format(int(16777238),"x").zfill(8))   #Auth-Application-ID Gx
        avp += self.generate_avp(285, 40, format(int(0),"x").zfill(8))   #Re-Auth Request TYpe
        response = self.generate_diameter_packet("01", "c0", 258, 16777238, self.generate_id(4), self.generate_id(4), avp)     #Generate Diameter packet
        return response
    
    #3GPP AAA Answer 
    def Answer_16777236_265(self, packet_vars, avps):
        try:
            """
            Generates a response to a provided AAR.
            The response is determined by whether or not the subscriber is enabled, and has a matching ims_subscriber entry.
            """
            avp = ''
            sessionId = bytes.fromhex(self.get_avp_data(avps, 263)[0]).decode('ascii')                                          #Get Session-ID
            avp += self.generate_avp(263, 40, self.string_to_hex(sessionId))                                                    #Set session ID to received session ID
            avp += self.generate_avp(258, 40, format(int(16777236),"x").zfill(8))
            avp += self.generate_avp(264, 40, self.OriginHost)                                               #Origin Host
            avp += self.generate_avp(296, 40, self.OriginRealm)                                              #Origin Realm
            subscriptionId = bytes.fromhex(self.get_avp_data(avps, 444)[0]).decode('ascii')
            subscriptionId = subscriptionId.replace('sip:', '')
            imsi = None
            msisdn = None
            identifier = None
            if '@' in subscriptionId:
                subscriberIdentifier = subscriptionId.split('@')[0]
                # Subscriber Identifier can be either an IMSI or an MSISDN
                try:
                    # subscriberDetails = self.database.Get_Subscriber(imsi=subscriberIdentifier)
                    # imsSubscriberDetails = self.database.Get_IMS_Subscriber(imsi=subscriberIdentifier)
                    identifier = 'imsi'
                    # imsi = imsSubscriberDetails.get('imsi', None)
                except Exception as e:
                    pass
                try:
                    # subscriberDetails = self.database.Get_Subscriber(msisdn=subscriberIdentifier)
                    # imsSubscriberDetails = self.database.Get_IMS_Subscriber(msisdn=subscriberIdentifier)
                    identifier = 'msisdn'
                    # msisdn = imsSubscriberDetails.get('msisdn', None)
                except Exception as e:
                    pass
            else:
                imsi = None
                msisdn = None
            # self.logTool.log(service='HSS', level='debug', message=f"[diameter.py] [Answer_16777236_265] [AAA] IMSI: {imsi}\nMSISDN: {msisdn}", redisClient=self.redisMessaging)
            # imsEnabled = self.validateImsSubscriber(imsi=imsi, msisdn=msisdn)

            # if imsEnabled:
            #     """
            #     Add the PCSCF to the IMS_Subscriber object, and set the result code to 2001.
            #     """
            #     # self.logTool.log(service='HSS', level='debug', message=f"[diameter.py] [Answer_16777236_265] [AAA] Request authorized", redisClient=self.redisMessaging)

            #     if imsi is None:
            #         # imsi = subscriberDetails.get('imsi', None)
            #         print('Hello')
            #     aarOriginHost = self.get_avp_data(avps, 264)[0]
            #     aarOriginHost = bytes.fromhex(aarOriginHost).decode('ascii')
            #     aarOriginRealm = self.get_avp_data(avps, 296)[0]
            #     aarOriginRealm = bytes.fromhex(aarOriginRealm).decode('ascii')
            #     #Check if we have a record-route set as that's where we'll need to send the response
            #     try:
            #         #Get first record-route header, then parse it
            #         remotePeer = self.get_avp_data(avps, 282)[-1]
            #         remotePeer = binascii.unhexlify(remotePeer).decode('utf-8')
            #     except Exception as e:
            #         #If we don't have a record-route set, we'll send the response to the OriginHost
            #         remotePeer = aarOriginHost
                
            #     remotePeer = f"{remotePeer};{self.config['hss']['OriginHost']}"

            #     # self.database.Update_Proxy_CSCF(imsi=imsi, proxy_cscf=aarOriginHost, pcscf_realm=aarOriginRealm, pcscf_peer=remotePeer, pcscf_active_session=None)
            #     """
            #     Check for AVP's 504 (AF-Application-Identifier) and 520 (Media-Type), which indicates the UE is making a call.
            #     Media-Type: 0 = Audio, 4 = Control
            #     """
            #     try:
            #         afApplicationIdentifier = self.get_avp_data(avps, 504)[0]
            #         mediaType = self.get_avp_data(avps, 520)[0]
            #         assert(bytes.fromhex(afApplicationIdentifier).decode('ascii') == "IMS Services")
            #         assert(int(mediaType, 16) == 0)

            #         # At this point, we know the AAR is indicating a call setup, so we'll send get the serving pgw information, then send a 
            #         # RAR to the PGW over Gx, asking it to setup the dedicated bearer.

            #         try:
            #             # subscriberId = subscriberDetails.get('subscriber_id', None)
            #             # apnId = (self.database.Get_APN_by_Name(apn="ims")).get('apn_id', None)
            #             # servingApn = self.database.Get_Serving_APN(subscriber_id=subscriberId, apn_id=apnId)
            #             # servingPgwPeer = servingApn.get('serving_pgw_peer', None).split(';')[0]
            #             # servingPgw = servingApn.get('serving_pgw', None)
            #             # servingPgwRealm = servingApn.get('serving_pgw_realm', None)
            #             # pcrfSessionId = servingApn.get('pcrf_session_id', None)
            #             # ueIp = servingApn.get('subscriber_routing', None)

            #             ulBandwidth = 512000
            #             dlBandwidth = 512000

            #             try:
            #                 avpUlBandwidth = int((self.get_avp_data(avps, 516)[0]), 16)
            #                 avpDlBandwidth = int((self.get_avp_data(avps, 515)[0]), 16)

            #                 if avpUlBandwidth <= ulBandwidth:
            #                     ulBandwidth = avpUlBandwidth
                    
            #                 if avpDlBandwidth <= dlBandwidth:
            #                     dlBandwidth = avpDlBandwidth
            #             except Exception as e:
            #                 pass

            #             """
            #             The below logic is applied:
            #             1. Grab the Flow Rules and bitrates from the PCSCF in the AAR,
            #             2. Compare it to a given backup rule
            #             - If the flowrates are greater than the backup rule (UE is asking for more than allowed), use the backup rule
            #             - If the flowrates are lesser than the backup rule, use the requested flowrates.
            #             3. Send the winning rule.
            #             """

            #             chargingRule = {
            #             "charging_rule_id": 1000,
            #             "qci": 1,
            #             "arp_preemption_capability": True,
            #             "mbr_dl": dlBandwidth,
            #             "mbr_ul": ulBandwidth,
            #             "gbr_ul": ulBandwidth,
            #             "precedence": 100,
            #             "arp_priority": 2,
            #             "rule_name": "GBR-Voice",
            #             "arp_preemption_vulnerability": False,
            #             "gbr_dl": dlBandwidth,
            #             "tft_group_id": 1,
            #             "rating_group": None,
            #             "tft": [
            #                 {
            #                 "tft_group_id": 1,
            #                 "direction": 1,
            #                 "tft_id": 1,
            #                 "tft_string": "permit out 17 from {{ UE_IP }}/32 1-65535 to any 1-65535"
            #                 },
            #                 {
            #                 "tft_group_id": 1,
            #                 "direction": 2,
            #                 "tft_id": 2,
            #                 "tft_string": "permit out 17 from {{ UE_IP }}/32 1-65535 to any 1-65535"
            #                 }
            #             ]
            #             }

            #             # self.database.Update_Proxy_CSCF(imsi=imsi, proxy_cscf=aarOriginHost, pcscf_realm=aarOriginRealm, pcscf_peer=remotePeer, pcscf_active_session=sessionId)

            #             reAuthAnswer = self.awaitDiameterRequestAndResponse(
            #                     requestType='RAR',
            #                     hostname=servingPgwPeer,
            #                     sessionId=pcrfSessionId,
            #                     chargingRules=chargingRule,
            #                     ueIp=ueIp,
            #                     servingPgw=servingPgw,
            #                     servingRealm=servingPgwRealm
            #             )

            #             if not len(reAuthAnswer) > 0:
            #                 # self.logTool.log(service='HSS', level='debug', message=f"[diameter.py] [Answer_16777236_265] [AAA] RAA Timeout: {reAuthAnswer}", redisClient=self.redisMessaging)
            #                 assert()
                            
            #             raaPacketVars, raaAvps = self.decode_diameter_packet(reAuthAnswer)
            #             raaResultCode = int(self.get_avp_data(raaAvps, 268)[0], 16)

            #             if raaResultCode == 2001:
            #                 avp += self.generate_avp(268, 40, self.int_to_hex(2001, 4))
            #                 # self.logTool.log(service='HSS', level='debug', message=f"[diameter.py] [Answer_16777236_265] [AAA] RAA returned Successfully, authorizing request", redisClient=self.redisMessaging)
            #             else:
            #                 avp += self.generate_avp(268, 40, self.int_to_hex(4001, 4))
            #                 # self.logTool.log(service='HSS', level='debug', message=f"[diameter.py] [Answer_16777236_265] [AAA] RAA returned Unauthorized, declining request", redisClient=self.redisMessaging)

            #         except Exception as e:
            #             # self.logTool.log(service='HSS', level='debug', message=f"[diameter.py] [Answer_16777236_265] [AAA] Error processing RAR / RAA, Authorizing request: {traceback.format_exc()}", redisClient=self.redisMessaging)
            #             avp += self.generate_avp(268, 40, self.int_to_hex(2001, 4))
                    
            #     except Exception as e:
            #         avp += self.generate_avp(268, 40, self.int_to_hex(2001, 4))
            #         pass
            # else:
                # self.logTool.log(service='HSS', level='debug', message=f"[diameter.py] [Answer_16777236_265] [AAA] Request unauthorized", redisClient=self.redisMessaging)
                # avp += self.generate_avp(268, 40, self.int_to_hex(2001, 4))
            
            response = self.generate_diameter_packet("01", "40", 265, 16777236, packet_vars['hop-by-hop-identifier'], packet_vars['end-to-end-identifier'], avp)     #Generate Diameter packet
            return response
        except Exception as e:
            # self.logTool.log(service='HSS', level='error', message=f"[diameter.py] [Answer_16777236_265] [AAA] Error generating AAA: {traceback.format_exc()}", redisClient=self.redisMessaging)
            avp = ''
            session_id = self.get_avp_data(avps, 263)[0]                                                     #Get Session-ID
            avp += self.generate_avp(263, 40, session_id)                                                    #Set session ID to received session ID
            avp += self.generate_avp(258, 40, format(int(16777272),"x").zfill(8))
            avp += self.generate_avp(274, 40, self.int_to_hex(2, 4))                   
            avp += self.generate_avp(264, 40, self.OriginHost)                                               #Origin Host
            avp += self.generate_avp(296, 40, self.OriginRealm)                                              #Origin Realm
            avp += self.generate_avp(268, 40, self.int_to_hex(2001, 4))                                      #Result Code 5012 UNABLE_TO_COMPLY
            response = self.generate_diameter_packet("01", "40", 265, 16777272, packet_vars['hop-by-hop-identifier'], packet_vars['end-to-end-identifier'], avp)     #Generate Diameter packet
            return response
