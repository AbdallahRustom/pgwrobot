*** Settings ***
Resource          resources/pgw_resource.robot
Library           python/csr.py
*** Test Cases ***
My First Test
    [Documentation]                Send Create Session Request 
    [Tags]                         First
    ${base_pkt} =                  create_session_request    ${srs_ip}    ${pgw_ip}     ${IMSI}   ${mcc}  ${mnc}  ${apn} 
    ${finalresult} =               Fire     ${interface}    ${base_pkt}   
    # Log To Console                 ${base_pkt}