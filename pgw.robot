*** Settings ***
Resource          resources/pgw_resource.robot
Library           python/gtppacket.py
Library           python/mydiameterscript.py
*** Test Cases ***
My Initilization 
    [Documentation]                Inializing Clients            
    establish_diam_tcp_connection 
    ${socket} =                      init_soc
    Set GTP Socket                   ${socket}
    # gtp_listener                     ${socket}  
    Sleep                            5s
My first Test
    [Documentation]                Send Create Session Request 
    [Tags]                         First
    ${base_pkt} =                  create_session_request    ${IMSI}     ${mcc}      ${mnc}      ${apn}    ${csrrattype}   ${csrinterfacetype}    ${bearercsrrattype}    ${csrinstance}    ${csrseq}   
    ${request} =                   send_gtpv2_message        ${socket}       ${pgw_ip}    ${csrport}     ${base_pkt}    
    ${response} =                  get_gtp_response          ${socket}
    Set IPAddress and GREID        ${response}
    Log To Console                 ${ip_address}
    Validate Response              ${ip_address}
    # Log To Console                ${response}
    Sleep                          5s
My Second Test
    [Documentation]                Testing S6b interface 
    [Tags]                         Second
    ${base_pkt} =                  create_session_request    ${s6bIMSI}     ${mcc}      ${mnc}      ${apn}    ${s6brattype}   ${s6binterfacetype}   ${s6bbearerinterfacetype}    ${s6binstance}     ${s6bseq}  
    ${request} =                   send_gtpv2_message        ${socket}        ${pgw_ip}    ${csrport}     ${base_pkt}   
    ${response} =                  get_gtp_response          ${socket}
    Set s6bIPAddress and s6bGREID  ${response}
    Log To Console                 ${s6b_ip_address}
    Validate Response              ${s6b_ip_address}
    Sleep                          5s
My Third Test
    [Documentation]                Testing Modify bearer Request  
    [Tags]                         Third
    ${base_pkt} =                  modify_bearer_request   ${gre_key}  
    ${request} =                   send_gtpv2_message    ${socket}    ${pgw_ip}    ${csrport}    ${base_pkt}
    ${response} =                  get_gtp_response          ${socket}    
    # Log To Console                 ${response}    
    Set Cause and modify GREID     ${response}
    Log To Console                 ${cause}               
    Validate Cause                 ${cause}
    Sleep                          5s
My Forth Test
    [Documentation]                Testing Create Bearer Request  
    [Tags]                         Forth
    send_auth_request
    ${result}=                     get_gtp_response    ${socket}     
    Set CBreq and CBRes_base_pkt   ${result}
    Log To Console                 ${cbreq}
    Validate CB GTP Request        ${cbreq}
    send_gtpv2_message             ${socket}    ${pgw_ip}    ${csrport}    ${cbreq_base_pkt}      
    Sleep                          5s
My Fifth Test
    [Documentation]                Testing Delete Bearer Request  
    [Tags]                         Fifth
    send_delete_auth_request
    ${result}=                     get_gtp_response    ${socket}
    Set DBreq and DBRes_base_pkt   ${result}
    Log To Console                 ${dbreq} 
    Validate DB GTP Request        ${dbreq}
    send_gtpv2_message             ${socket}    ${pgw_ip}    ${csrport}    ${dbreq_base_pkt}   
    Sleep                          5s
My Sixth Test
    [Documentation]                Testing Delete session Request  
    [Tags]                         Sixth
    ${base_pkt} =                  delete_session_request    ${mcc}      ${mnc}       ${gre_key}
    ${request} =                   send_gtpv2_message        ${socket}       ${pgw_ip}    ${csrport}     ${base_pkt}
    ${cause} =                     get_gtp_response          ${socket}    
    Log To Console                 ${cause}
    Validate Cause                 ${cause}
    Sleep                          5s
My Seventh Test 
    [Documentation]                Closing Clients
    [Tags]                         Seventh
    close_tcp_session