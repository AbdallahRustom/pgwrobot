from ipaddress import IPv4Address
from scapy.all import *
from scapy.contrib.gtp_v2 import *
from scapy.layers.inet import UDP
import socket


def create_session_request(IMSI,mcc,mnc,apn,rattype,interfacetype,bearerinterfacetype,instance,seq,epi,qci):
    apn_length = len(apn) + 1
    base_pkt = (
        GTPHeader(
            seq=seq,
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
                IE_BearerContext(
                    ietype=93,
                    length=44,
                    CR_flag=0,
                    instance=0,
                    IE_list=[
                        IE_EPSBearerID(ietype=73, length=1, CR_flag=0, instance=0, EBI=epi),
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
                            QCI=qci,
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

def modify_bearer_request(gre_key):
    base_pkt = (
        GTPHeader(
            seq=5667215,
            version=2,
            P=0,
            T=1,
            MP=0,
            SPARE1=0,
            SPARE2=0,
            gtp_type=34,
            teid=gre_key,
            SPARE3=0,
        )
        / IE_BearerContext(
            ietype=93,
            length=18,
            CR_flag=0,
            instance=0,
            IE_list=[
                IE_EPSBearerID(ietype=73, length=1, CR_flag=0, instance=0, EBI=5),
                IE_FTEID(
                    ietype=87,
                    length=9,
                    CR_flag=0,
                    instance=0,
                    ipv4_present=1,
                    ipv6_present=0,
                    InterfaceType=0,
                    GRE_Key=0xD56DC020,
                    ipv4="192.168.134.50",
                ),
            ]
        )           
    )
    return base_pkt

def create_bearer_response(teid,seq,gre_key,pgw_ip):
    base_pkt = (
        GTPHeader(
            seq=seq,
            version=2,
            P=0,
            T=1,
            MP=0,
            gtp_type=96,
            teid=teid,
            SPARE3=0,
        )/IE_Cause(ietype=2,length=2,CR_flag=0,instance=0,Cause=16)
        / IE_BearerContext(
            ietype=93,
            length=37,
            CR_flag=0,
            instance=0,
            IE_list=[    
                IE_EPSBearerID(ietype=73, length=1, CR_flag=0, instance=0, EBI=7),
                IE_FTEID(
                    ietype=87,
                    length=9,
                    CR_flag=0,
                    instance=2,
                    ipv4_present=1,
                    ipv6_present=0,
                    InterfaceType=4,
                    GRE_Key=0xD56DC020,
                    ipv4="10.0.3.4",
                ),
                IE_FTEID(
                    ietype=87,
                    length=9,
                    CR_flag=0,
                    instance=3,
                    ipv4_present=1,
                    ipv6_present=0,
                    InterfaceType=5,
                    GRE_Key=gre_key,
                    ipv4=pgw_ip,
                ),
                IE_Cause(ietype=2,length=2,CR_flag=0,instance=0,Cause=16),
            ]    
        )
        /IE_UE_Timezone(ietype=114,length=2,CR_flag=0,instance=0,DST=0)
        /IE_ULI(ietype=86,length=13,CR_flag=0,instance=0,ECGI_Present=1,TAI_Present=1) 
        /ULI_TAI(MCC="01",MNC="01",TAC=1)
        /ULI_ECGI(MCC="01",MNC="01",ECI=1)       
    )
    return base_pkt

def delete_bearer_response(teid,seq):
    base_pkt = (
        GTPHeader(
            seq=seq,
            version=2,
            P=0,
            T=1,
            MP=0,
            gtp_type=100,
            teid=teid,
            SPARE3=0,
        )/IE_Cause(ietype=2,length=2,CR_flag=0,instance=0,Cause=16)
        / IE_BearerContext(
            ietype=93,
            length=11,
            CR_flag=0,
            instance=0,
            IE_list=[    
                IE_EPSBearerID(ietype=73, length=1, CR_flag=0, instance=0, EBI=7),
                IE_Cause(ietype=2,length=2,CR_flag=0,instance=0,Cause=16),
            ]    
        )
        /IE_UE_Timezone(ietype=114,length=2,CR_flag=0,instance=0,DST=0)
        /IE_ULI(ietype=86,length=13,CR_flag=0,instance=0,ECGI_Present=1,TAI_Present=1) 
        /ULI_TAI(MCC="01",MNC="01",TAC=1)
        /ULI_ECGI(MCC="01",MNC="01",ECI=1)           
    )
    return base_pkt



def delete_session_request(mcc,mnc,gre_key,seq,epi):
    base_pkt = (
        GTPHeader(
            seq=seq,
            version=2,
            P=0,
            T=1,
            MP=0,
            SPARE1=0,
            SPARE2=0,
            gtp_type=36,
            teid=gre_key,
            SPARE3=0,
        )
        / GTPV2DeleteSessionRequest(
            IE_list=[
                IE_EPSBearerID(ietype=73, length=1, CR_flag=0, instance=0, EBI=epi),
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
                IE_Indication(
                    ietype=77, 
                    length=4,          
                    CR_flag=0, 
                    instance=0, 
                    DAF=0,
                    DTF=0,
                    HI=0,
                    DFI=0,
                    OI=1,
                    ISRSI=0,
                    ISRAI=0,
                    SGWCI=0,
                    SQCI=0,
                    UIMSI=0,
                    CFSI=0,
                    CRSI=0,
                    PS=0,
                    PT=0,
                    SI=0,
                    MSV=0,
                    RetLoc=0,
                    PBIC=0,
                    SRNI=0,
                    S6AF=0,
                    S4AF=0,
                    MBMDT=0,
                    ISRAU=0,
                    CCRSI=0,
                    CPRAI=0,
                    ARRL=0,
                    PPOFF=0,
                    PPON=0,
                    PPSI=0,
                    CSFBI=0,
                    CLII=0,
                    CPSR=0,
                    NSI=0,
                    UASI=0,
                    DTCI=0,
                    BDWI=0,
                    PSCI=0,
                    PCRI=0,
                    AOSI=0,
                    AOPI=0,
                    ROAAI=0,
                    EPCOSI=0,
                    CPOPCI=0,
                    PMTSMI=0,
                    S11TF=0,
                    PNSI=0,
                    UNACCSI=0,
                    WPMSI=0,
                    REPREFI=0,
                    EEVRSI=0,
                    LTEMUI=0,
                    LTEMPI=0,
                    ENBCRSI=0,
                    TSPCMI=0,    
                ),  
            ]
        )
    )
    return base_pkt

def init_soc():
    s=socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    return s   


def send_gtpv2_message(s,ip, port, message):
    s.sendto(bytes(message), (ip, port))
    

def decode_gtpv2_response(data): 
    decoded_message= GTPHeader(data)
    
    if GTPV2CreateSessionResponse in decoded_message:
        IE_Cause=decoded_message.IE_list[0].Cause    
        ipaddress=parse_ipv4_address(decoded_message)
        gre_key=parse_gre_key_from_response(decoded_message)
        return IE_Cause,ipaddress,gre_key
    
    elif GTPV2ModifyBearerResponse in decoded_message:
        IE_Cause= decoded_message[GTPV2ModifyBearerResponse].IE_list[0].Cause
        teid=decoded_message[GTPHeader].teid
        return IE_Cause,teid
    
    elif GTPV2CreateBearerRequest in decoded_message:
        teid=decoded_message[GTPHeader].teid
        seq=decoded_message[GTPHeader].seq
        fteid_ie = decoded_message[GTPV2CreateBearerRequest].getlayer(IE_FTEID)
        gre_key = fteid_ie.GRE_Key
        pgw_ip= fteid_ie.ipv4          
        base_bk= create_bearer_response(teid,seq,gre_key,pgw_ip)
        return  decoded_message,base_bk
    
    elif GTPV2DeleteBearerRequest in decoded_message:
        teid=decoded_message[GTPHeader].teid
        seq=decoded_message[GTPHeader].seq
        base_bk= delete_bearer_response(teid,seq)
        return decoded_message,base_bk  

    elif GTPV2DeleteSessionResponse in decoded_message:
        IE_Cause= decoded_message[GTPV2DeleteSessionResponse].IE_list[0].Cause
        return IE_Cause  
    
    return None

def parse_ipv4_address(response):
    gtp_response = response[GTPHeader]
    ie_list = gtp_response[GTPV2CreateSessionResponse].getfieldval("IE_list")
    for ie in ie_list:
            if isinstance(ie, IE_PAA):
                ipv4_address = IPv4Address(ie.ipv4)
                return ipv4_address
    return None


def parse_gre_key_from_response(response):
    fteid_ie = response[GTPV2CreateSessionResponse].getlayer(IE_FTEID)
    if fteid_ie:
        gre_key = fteid_ie.GRE_Key
        return gre_key
    return None

def get_gtp_response(s, 5):
    s.settimeout(timeout_seconds)
    try:
        data, addr = s.recvfrom(1024)
        decoded_message = decode_gtpv2_response(data)
        return decoded_message
    except socket.timeout:
        return None
        
