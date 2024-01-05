*** Settings ***
Library                             OperatingSystem
*** Variables ***
${srs_ip} =                         127.0.0.10
${pgw_ip} =                         127.0.0.4
${IMSI} =                           001011234567895
${s6bIMSI} =                        001011234567896 
${mcc} =                            001
${mnc} =                            01
${apn} =                            internet
${imsapn} =                         ims
${interface} =                      lo
${csrseq} =                         ${5667214}
${s6bseq} =                         ${5667220}
${imsseq} =                         ${5667225}
${csrrattype} =                     ${6}
${s6brattype} =                     ${3}
${csrinterfacetype} =               ${6}
${s6binterfacetype} =               ${30}
${bearercsrrattype} =               ${4}
${s6bbearerinterfacetype} =         ${31}
${csrinstance} =                    ${2}  
${s6binstance} =                    ${5}
${csrport} =                        ${2123}
${internetepi} =                    ${5}
${imsepi} =                         ${6}
${internetqci} =                    ${9}
${imsqci} =                         ${5}
${deletesessionseq} =               ${5667216}
${s6bdeletesessionseq} =            ${5667217}
${imsdeletesessionseq} =            ${5667218}
${ip_address}=                      Set Variable    ${EMPTY}
${gre_key}=                         Set Variable    ${EMPTY}
${s6b_ip_address}=                  Set Variable    ${EMPTY}
${s6b_gre_key}=                     Set Variable    ${EMPTY}
${ims_ip_address}=                  Set Variable    ${EMPTY}
${ims_gre_key}=                     Set Variable    ${EMPTY}
${cause}=                           Set Variable    ${EMPTY}
${modifiy_sess_gre_key}=            Set Variable    ${EMPTY}                  
${socket} =                         Set Variable    ${EMPTY}
${cbreq} =                          Set Variable    ${EMPTY}   
${cbreq_base_pkt} =                 Set Variable    ${EMPTY}
${dbreq} =                          Set Variable    ${EMPTY}   
${dbreq_base_pkt} =                 Set Variable    ${EMPTY}
*** Keywords ***
Set GTP Socket
    [Arguments]                     ${socket}              
    ${socket} =                     Set Variable    ${socket}   
    Set Suite Variable              ${socket}
Validate Response
    [Arguments]                     ${response}
    Should Not Be Equal As Strings  ${response}  None     
    Should Not Be Equal As Strings  ${response}  0.0.0.0  
Set IPAddress and GREID
    [Arguments]                     ${finalresult}
    ${ip_address}=                  Set Variable    ${finalresult[1]}
    ${gre_key}=                     Set Variable    ${finalresult[2]}
    Set Suite Variable              ${ip_address}    
    Set Suite Variable              ${gre_key}
Set IMS IPAddress and GREID
    [Arguments]                     ${finalresult}
    ${ims_ip_address}=                  Set Variable    ${finalresult[1]}
    ${ims_gre_key}=                     Set Variable    ${finalresult[2]}
    Set Suite Variable              ${ims_ip_address}    
    Set Suite Variable              ${ims_gre_key}

Set s6bIPAddress and s6bGREID
    [Arguments]                     ${finalresult}
    ${s6b_ip_address}=              Set Variable    ${finalresult[1]}
    ${s6b_gre_key}=                 Set Variable    ${finalresult[2]}
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
Validate CB GTP Request
    [Arguments]        ${response}
    ${expected_value}    Set Variable    GTPV2CreateBearerRequest
    Should Contain       ${response}     ${expected_value}   
Validate DB GTP Request
    [Arguments]        ${response}
    ${expected_value}    Set Variable    GTPV2DeleteBearerRequest
    Should Contain       ${response}     ${expected_value} 

Set CBreq and CBRes_base_pkt
    [Arguments]                     ${result}
    ${cbreq}=                       Set Variable    ${result[0]}
    ${cbreq_base_pkt}=              Set Variable    ${result[1]}
    Set Suite Variable              ${cbreq}    
    Set Suite Variable              ${cbreq_base_pkt}

Set DBreq and DBRes_base_pkt
    [Arguments]                     ${result}
    ${dbreq}=                       Set Variable    ${result[0]}
    ${dbreq_base_pkt}=              Set Variable    ${result[1]}
    Set Suite Variable              ${dbreq}    
    Set Suite Variable              ${dbreq_base_pkt}