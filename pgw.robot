*** Settings ***
Resource          resources/pgw_resource.robot
Library           python/csr.py
*** Test Cases ***
My First Test
    [Documentation]                Send Create Session Request 
    [Tags]                         First
    ${base_pkt} =                  create_session_request    ${srs_ip}    ${pgw_ip}     ${IMSI}     ${mcc}      ${mnc}      ${apn}    ${csrrattype}   ${csrinterfacetype}    ${bearercsrrattype}    ${csrinstance}  ${csrport}  
    ${finalresult} =               Fire Recive     ${interface}    ${base_pkt}   
    Log To Console                 ${finalresult}
    Validate Response              ${finalresult}
My Second Test
    [Documentation]                Testing S6b interface 
    [Tags]                         Second
    ${base_pkt} =                  create_session_request    ${srs_ip}    ${pgw_ip}     ${s6bIMSI}     ${mcc}      ${mnc}      ${apn}    ${s6brattype}   ${s6binterfacetype}   ${s6bbearerinterfacetype}    ${s6binstance}     ${s6bport}    
    ${finalresult} =               Fire Recive     ${interface}    ${base_pkt}   
    Log To Console                 ${finalresult}
    Validate Response              ${finalresult}