*** Settings ***
Resource          resources/pgw_resource.robot
Library           python/gtppacket.py
Library           python/mydiameterscript.py
*** Test Cases ***
My Initilization 
    [Documentation]                Inializing Clients            
    establish_diam_tcp_connection 
    ${object} =                    initilize_gtpcommunicator    ${interface}
    initilize_gtp_clinet           ${object} 
    Set Gtp object                 ${object}                            
    Sleep                          5s
My first Test
    [Documentation]                Send Create Session Request 
    [Tags]                         First
    ${base_pkt} =                  create_session_request    ${srs_ip}    ${pgw_ip}     ${IMSI}     ${mcc}      ${mnc}      ${apn}    ${csrrattype}   ${csrinterfacetype}    ${bearercsrrattype}    ${csrinstance}  ${csrport}  
    sent_gtp_request               ${object}   ${base_pkt}
    ${response}                    get_gtp_response     ${object}    
    Set IPAddress and GREID        ${response}
    Log To Console                 ${ip_address}
    Validate Response              ${ip_address}
    Sleep                          5s
My Second Test
    [Documentation]                Testing S6b interface 
    [Tags]                         Second
    ${base_pkt} =                  create_session_request    ${srs_ip}    ${pgw_ip}     ${s6bIMSI}     ${mcc}      ${mnc}      ${apn}    ${s6brattype}   ${s6binterfacetype}   ${s6bbearerinterfacetype}    ${s6binstance}     ${s6bport}    
    sent_gtp_request               ${object}   ${base_pkt}
    ${response}                    get_gtp_response     ${object}    
    Set s6bIPAddress and s6bGREID  ${response}
    Log To Console                 ${ip_address}
    Validate Response              ${ip_address}
    Sleep                          5s
My Third Test
    [Documentation]                Testing Modify bearer Request  
    [Tags]                         Third
    ${base_pkt} =                  modify_bearer_request   ${srs_ip}    ${pgw_ip}       ${csrport}      ${gre_key}  
    sent_gtp_request               ${object}   ${base_pkt}
    ${response}                    get_gtp_response     ${object}    
    Log To Console                 ${response}    
    Set Cause and modify GREID     ${response}
    Log To Console                 ${cause}               
    Validate Cause                 ${cause}
    Sleep                          5s
My Forth Test
    [Documentation]                Testing Create Bearer Request  
    [Tags]                         Forth
    send_auth_request
    ${response}                    get_gtp_response     ${object}
    Log To Console                 ${response} 
    Validate CB GTP Request        ${response}   
    Sleep                          5s
My Fifth Test
    [Documentation]                Testing Delete Bearer Request  
    [Tags]                         Fifth
    send_delete_auth_request
    ${response}                    get_gtp_response     ${object}
    Log To Console                 ${response} 
    Validate DB GTP Request        ${response}   
    Sleep                          5s
My Sixth Test
    [Documentation]                Testing Delete session Request  
    [Tags]                         Sixth
    ${base_pkt} =                  delete_session_request    ${srs_ip}    ${pgw_ip}     ${mcc}      ${mnc}       ${gre_key}      ${csrport}  
    sent_gtp_request               ${object}   ${base_pkt}
    ${response}                    get_gtp_response     ${object}    
    Log To Console                 ${cause}
    Validate Cause                 ${cause}
    Sleep                          5s
My Seventh Test 
    [Documentation]                Closing Clients
    [Tags]                         Seventh
    close_tcp_session
    stop_listener                  ${object}