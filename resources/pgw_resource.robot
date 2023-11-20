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
*** Keywords ***
Validate Response
    [Arguments]                    ${response}
    Should Not Be Equal As Strings  ${response}  None     # Check if the response is None
    Should Not Be Equal As Strings  ${response}  0.0.0.0  # Check if the response is "0.0.0.0"