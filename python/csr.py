from scapy.all import *
from scapy.contrib import gtp
from scapy.contrib.gtp_v2 import *
from scapy.all import conf
from scapy.layers.inet import IP, UDP, Ether
from ipaddress import IPv4Address, IPv4Network, AddressValueError
import logging
from time import time

def create_session_request(srs_ip,pgw_ip,IMSI,mcc,mnc,apn,rattype,interfacetype,bearerinterfacetype,instance,port):
    apn_length = len(apn) + 1
    base_pkt = (
        IP(
            version=4,
            ihl=5,
            tos=0,
            id=0,
            flags=0,
            frag=0,
            ttl=255,
            proto=17,
            src=srs_ip,
            dst=pgw_ip,
        )
        / UDP(sport=port, dport=2123, chksum=0)
        / GTPHeader(
            seq=5667214,
            version=2,
            P=0,
            T=1,
            MP=0,
            SPARE1=0,
            SPARE2=0,
            gtp_type=32,
            teid=0,
            SPARE3=0,
        )
        / GTPV2CreateSessionRequest(
            IE_list=[
                IE_IMSI(ietype=1, length=8, CR_flag=0, instance=0, IMSI=IMSI),
                IE_MSISDN(ietype=76, length=6, CR_flag=0, instance=0, digits="79161111111"),
                IE_MEI(ietype=75, length=8, CR_flag=0, instance=0, MEI="3584311111111111"),
                IE_ULI(
                    ietype=86,
                    length=13,
                    CR_flag=0,
                    instance=0,
                    SPARE=0,
                    LAI_Present=0,
                    ECGI_Present=1,
                    TAI_Present=1,
                    RAI_Present=0,
                    SAI_Present=0,
                    CGI_Present=0,
                    TAI=ULI_TAI(MCC=mcc, MNC=mnc, TAC=15404),
                    ECGI=ULI_ECGI(MCC=mcc, MNC=mnc, SPARE=0, ECI=176130090),
                ),
                IE_ServingNetwork(
                    ietype=83, length=3, CR_flag=0, instance=0, MCC=mcc, MNC=mnc
                ),
                IE_RAT(ietype=82, length=1, CR_flag=0, instance=0, RAT_type=rattype),
                IE_FTEID(
                    ietype=87,
                    length=9,
                    CR_flag=0,
                    instance=0,
                    ipv4_present=1,
                    ipv6_present=0,
                    InterfaceType=interfacetype,
                    GRE_Key=0x00000000,
                    ipv4="192.168.134.129",
                ),
                IE_APN(ietype=71, length=apn_length, CR_flag=0, instance=0, APN=apn),
                IE_SelectionMode(
                    ietype=128, length=1, CR_flag=0, instance=0, SPARE=0, SelectionMode=0
                ),
                IE_PDN_type(
                    ietype=99, length=1, CR_flag=0, instance=0, SPARE=0, PDN_type=3
                ),
                IE_PAA(
                    ietype=79,
                    length=22,
                    CR_flag=0,
                    instance=0,
                    SPARE=0,
                    PDN_type=3,
                    ipv6_prefix_length=0,
                    ipv6=0x0,
                    ipv4="0.0.0.0",
                ),
                IE_Indication(ietype=77, length=7, CR_flag=0, instance=0, DAF=1, PS=1),
                IE_APN_Restriction(
                    ietype=127, length=1, CR_flag=0, instance=0, APN_Restriction=0
                ),
                IE_AMBR(
                    ietype=72,
                    length=8,
                    CR_flag=0,
                    instance=0,
                    AMBR_Uplink=314573,
                    AMBR_Downlink=314573,
                ),
                # IE_PCO(
                #     ietype=78,
                #     length=50,
                #     CR_flag=0,
                #     instance=0,
                #     Extension=1,
                #     SPARE=0,
                #     PPP=0,
                #     Protocols=[
                #         PCO_IPCP(
                #             length=16,
                #             PPP=PCO_PPP(
                #                 Code=1,
                #                 Identifier=0,
                #                 length=16,
                #                 Options=[
                #                     PCO_Primary_DNS(length=6, address="0.0.0.0"),
                #                     PCO_Secondary_DNS(length=6, address="0.0.0.0"),
                #                 ],
                #             ),
                #         ),
                #         PCO_DNS_Server_IPv4(length=0),
                #         PCO_DNS_Server_IPv6(length=0),
                #         PCO_IP_Allocation_via_NAS(length=0),
                #         PCO_SOF(length=0),
                #         PCO_IPv4_Link_MTU_Request(length=0),
                #         PCO_PasswordAuthentificationProtocol(
                #             length=12,
                #             PPP=PCO_PPP_Auth(
                #                 Code=1,
                #                 Identifier=0,
                #                 length=12,
                #                 PeerID_length=3,
                #                 PeerID="mts",
                #                 Password_length=3,
                #                 Password="mts",
                #             ),
                #         ),
                #     ],
                # ),
                IE_BearerContext(
                    ietype=93,
                    length=44,
                    CR_flag=0,
                    instance=0,
                    IE_list=[
                        IE_EPSBearerID(ietype=73, length=1, CR_flag=0, instance=0, EBI=5),
                        IE_FTEID(
                            ietype=87,
                            length=9,
                            CR_flag=0,
                            instance=instance,
                            ipv4_present=1,
                            ipv6_present=0,
                            InterfaceType=bearerinterfacetype,
                            GRE_Key=0xD56DC018,
                            ipv4="192.168.134.129",
                        ),
                        IE_Bearer_QoS(
                            ietype=80,
                            length=22,
                            CR_flag=0,
                            instance=0,
                            SPARE1=0,
                            PCI=1,
                            PriorityLevel=3,
                            SPARE2=0,
                            PVI=0,
                            QCI=9,
                            MaxBitRateForUplink=0,
                            MaxBitRateForDownlink=0,
                            GuaranteedBitRateForUplink=0,
                            GuaranteedBitRateForDownlink=0,
                        ),
                    ],
                ),
                IE_UE_Timezone(
                    ietype=114, length=2, CR_flag=0, instance=0, Timezone=130, DST=0
                ),
                IE_ChargingCharacteristics(
                    ietype=95,
                    length=2,
                    CR_flag=0,
                    instance=0,
                    ChargingCharacteristric=0x800,
                ),
            ]
        )
    )
    return base_pkt

def fire_recive(interface,base_pkt):
    try:
        s = conf.L3socket(iface=interface)
    except OSError as e :
        logging.error(f"Error: {e}")
        logging.error(f"No such interface: {interface}")
        exit(1)
    
    teid = base_pkt[GTPHeader].teid    
    s.send(base_pkt)
    response = parse_response(teid,s)
    if response:
        pdn_ip_address= parse_ipv4_address(response)
    else:
        return None
    
    return pdn_ip_address

def parse_response(teid,s):
    start_time = time()
    timeout=10
    while time() - start_time <= timeout:
        response = s.recv(4096)
        if (
            response is not None
            and IP in response
            and UDP in response
            and GTPHeader in response
            and response[GTPHeader].teid == teid
        ):
            return response
    return None
    
def parse_ipv4_address(response):
    gtp_response = response[GTPHeader]
    ie_list = gtp_response[GTPV2CreateSessionResponse].getfieldval("IE_list")
    for ie in ie_list:
            if isinstance(ie, IE_PAA):
                ipv4_address = IPv4Address(ie.ipv4)
                return ipv4_address
    return None