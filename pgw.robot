*** Settings ***
Resource          resources/pgw_resource.robot
Library           python/gtppacket.py
Library           python/mydiameterscript.py
*** Test Cases ***
My Initilization 
    [Documentation]                Inializing Clients            
    establish_diam_tcp_connection 
    ${socket} =                    init_soc
    Set GTP Socket                 ${socket}
    Sleep                          5s
My First Test
    [Documentation]                Send Create Session Request 
    [Tags]                         First
    ${base_pkt} =                  create_session_request    ${IMSI}     ${mcc}      ${mnc}      ${apn}    ${csrrattype}   ${csrinterfacetype}    ${bearercsrrattype}    ${csrinstance}    ${csrseq}  ${internetepi}     ${internetqci} 
    ${request} =                   send_gtpv2_message        ${socket}   ${pgw_ip}   ${csrport}  ${base_pkt}    
    ${response} =                  get_gtp_response          ${socket}
    Set IPAddress and GREID        ${response}
    Log To Console                 ${ip_address}
    Validate Response              ${ip_address}
    Sleep                          5s
My Second Test
    [Documentation]                Testing S6b interface 
    [Tags]                         Second
    ${base_pkt} =                  create_session_request    ${s6bIMSI}     ${mcc}      ${mnc}      ${apn}    ${s6brattype}   ${s6binterfacetype}   ${s6bbearerinterfacetype}    ${s6binstance}     ${s6bseq}  ${internetepi}    ${internetqci}
    ${request} =                   send_gtpv2_message        ${socket}      ${pgw_ip}   ${csrport}  ${base_pkt}   
    ${response} =                  get_gtp_response          ${socket}
    Set s6bIPAddress and s6bGREID  ${response}
    Log To Console                 ${s6b_ip_address}
    Validate Response              ${s6b_ip_address}
    Sleep                          5s
My Third Test
    [Documentation]                Send IMS Create Session Request 
    [Tags]                         Third
    ${base_pkt} =                  create_session_request    ${IMSI}     ${mcc}      ${mnc}      ${imsapn}    ${csrrattype}   ${csrinterfacetype}    ${bearercsrrattype}    ${csrinstance}    ${imsseq}   ${imsepi}    ${imsqci} 
    ${request} =                   send_gtpv2_message        ${socket}   ${pgw_ip}   ${csrport}  ${base_pkt}    
    ${response} =                  get_gtp_response          ${socket}
    Set IMS IPAddress and GREID    ${response}
    Log To Console                 ${ims_ip_address}
    Validate Response              ${ims_ip_address}
    Sleep                          5s
My Forth Test
    [Documentation]                Testing Modify bearer Request  
    [Tags]                         Forth
    ${base_pkt} =                  modify_bearer_request    ${gre_key}  
    ${request} =                   send_gtpv2_message       ${socket}       ${pgw_ip}   ${csrport}   ${base_pkt}
    ${response} =                  get_gtp_response         ${socket}    
    # Log To Console                 ${response}    
    Set Cause and modify GREID     ${response}
    Log To Console                 ${cause}               
    Validate Cause                 ${cause}
    Sleep                          5s
My Fifth Test
    [Documentation]                Testing Create Bearer Request  
    [Tags]                         Fifth
    send_auth_request
    ${result}=                     get_gtp_response    ${socket}     
    Set CBreq and CBRes_base_pkt   ${result}
    Log To Console                 ${cbreq}
    Validate CB GTP Request        ${cbreq}
    send_gtpv2_message             ${socket}    ${pgw_ip}    ${csrport}    ${cbreq_base_pkt}      
    Sleep                          5s
My Sixth Test
    [Documentation]                Testing Delete Bearer Request  
    [Tags]                         Six
    send_delete_auth_request
    ${result}=                     get_gtp_response    ${socket}
    Set DBreq and DBRes_base_pkt   ${result}
    Log To Console                 ${dbreq} 
    Validate DB GTP Request        ${dbreq}
    send_gtpv2_message             ${socket}    ${pgw_ip}    ${csrport}    ${dbreq_base_pkt}   
    Sleep                          5s
My Seventh Test
    [Documentation]                Testing Delete session Request  
    [Tags]                         Seven
    ${base_pkt} =                  delete_session_request    ${mcc}      ${mnc}       ${gre_key}     ${deletesessionseq}    ${internetepi}    
    ${request} =                   send_gtpv2_message        ${socket}   ${pgw_ip}    ${csrport}     ${base_pkt}
    ${cause} =                     get_gtp_response          ${socket}    
    Log To Console                 ${cause}
    Validate Cause                 ${cause}
    # ${base_pkt} =                  delete_session_request    ${mcc}      ${mnc}       ${s6b_gre_key}  ${s6bdeletesessionseq}  ${internetepi}   
    # ${request} =                   send_gtpv2_message        ${socket}   ${pgw_ip}    ${csrport}      ${base_pkt}
    ${base_pkt} =                  delete_session_request    ${mcc}      ${mnc}       ${ims_gre_key}  ${imsdeletesessionseq}  ${imsqci} 
    ${request} =                   send_gtpv2_message        ${socket}   ${pgw_ip}    ${csrport}      ${base_pkt}
    Sleep                          5s
My Eighth Test 
    [Documentation]                Closing Clients
    [Tags]                         Eight
    close_tcp_session