*** Settings ***
Resource          resources/pgw_resource.robot
Library           python/csr.py
*** Test Cases ***
My First Test
    [Documentation]                Send Create Session Request 
    [Tags]                         First
    ${base_pkt} =                  create_session_request    ${srs_ip}    ${pgw_ip}     ${IMSI}     ${mcc}      ${mnc}      ${apn}    ${csrrattype}   ${csrinterfacetype}    ${bearercsrrattype}    ${csrinstance}  ${csrport}  
    ${finalresult} =               Fire Recive     ${interface}    ${base_pkt}
    Set IPAddress and GREID        ${finalresult}
    Log To Console                 ${ip_address}
    Log To Console                 ${gre_key}
    Validate Response              ${ip_address}
My Second Test
    [Documentation]                Testing S6b interface 
    [Tags]                         Second
    ${base_pkt} =                  create_session_request    ${srs_ip}    ${pgw_ip}     ${s6bIMSI}     ${mcc}      ${mnc}      ${apn}    ${s6brattype}   ${s6binterfacetype}   ${s6bbearerinterfacetype}    ${s6binstance}     ${s6bport}    
    ${finalresult} =               Fire Recive     ${interface}    ${base_pkt}
    Set s6bIPAddress and s6bGREID  ${finalresult}   
    Log To Console                 ${s6b_ip_address}
    Validate Response              ${s6b_ip_address}
My Third Test
    [Documentation]                Testing Modify bearer Request  
    [Tags]                         Third
    ${base_pkt} =                  modify_bearer_request   ${srs_ip}    ${pgw_ip}       ${csrport}      ${gre_key}  
    ${finalresult} =               Fire Recive     ${interface}    ${base_pkt}   
    Log To Console                 ${finalresult}
    Set Cause and modify GREID     ${finalresult}
    Validate Cause                 ${cause}
My Forth Test
    [Documentation]                Testing Delete session Request  
    [Tags]                         Forth
    ${base_pkt} =                  delete_session_request    ${srs_ip}    ${pgw_ip}     ${mcc}      ${mnc}       ${gre_key}     ${csrport}  
    ${finalresult} =               Fire Recive     ${interface}    ${base_pkt}   
    Log To Console                 ${finalresult}
    Validate Cause                 ${finalresult}