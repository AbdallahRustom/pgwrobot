*** Settings ***
Library                             OperatingSystem
*** Variables ***
${srs_ip} =                         10.1.1.16
${pgw_ip} =                         10.1.1.41
${IMSI} =                           001011234567895
${s6bIMSI} =                        001011234567896 
${mcc} =                            001
${mnc} =                            01
${apn} =                            internet
${interface} =                      ens160
${csrrattype} =                     ${6}
${s6brattype} =                     ${3}
${csrinterfacetype} =               ${6}
${s6binterfacetype} =               ${30}
${bearercsrrattype} =               ${4}
${s6bbearerinterfacetype} =         ${31}
${csrinstance} =                    ${2}  
${s6binstance} =                    ${5}
${csrport} =                        ${36368}
${s6bport} =                        ${36369}
${ip_address}=                      Set Variable    ${EMPTY}
${gre_key}=                         Set Variable    ${EMPTY}
${s6b_ip_address}=                  Set Variable    ${EMPTY}
${s6b_gre_key}=                     Set Variable    ${EMPTY}
${cause}=                           Set Variable    ${EMPTY}
${modifiy_sess_gre_key}=            Set Variable    ${EMPTY}                  
*** Keywords ***
Validate Response
    [Arguments]                    ${response}
    Should Not Be Equal As Strings  ${response}  None     
    Should Not Be Equal As Strings  ${response}  0.0.0.0  
Set IPAddress and GREID
    [Arguments]                     ${finalresult}
    ${ip_address}=                  Set Variable    ${finalresult[0]}
    ${gre_key}=                     Set Variable    ${finalresult[1]}
    Set Suite Variable              ${ip_address}    
    Set Suite Variable              ${gre_key}
Set s6bIPAddress and s6bGREID
    [Arguments]                     ${finalresult}
    ${s6b_ip_address}=              Set Variable    ${finalresult[0]}
    ${s6b_gre_key}=                 Set Variable    ${finalresult[1]}
    Set Suite Variable              ${s6b_ip_address}    
    Set Suite Variable              ${s6b_gre_key}
Set Cause and modify GREID
    [Arguments]                     ${finalresult}
    ${cause}=                       Set Variable    ${finalresult[0]}
    ${modifiy_sess_gre_key}=        Set Variable    ${finalresult[1]}
    Set Suite Variable              ${cause}    
    Set Suite Variable              ${modifiy_sess_gre_key}
Validate Cause
    [Arguments]                    ${response}
    Should Be Equal                ${response}  ${16}     
