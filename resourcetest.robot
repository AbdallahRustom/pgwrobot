*** Settings ***
Resource          resources/resource.robot
Library           python/calculator.py
*** Test Cases ***
My First Test
    [Documentation]                 Testing
    Log To Console                  ${Welcome}
My Second Test
    [Documentation]                 Creating File
    Create File                     new_file.txt            ${GOOD_TEXT}
    Log To Console                  Created File               
My Third Test
    [Documentation]                 Checking File Contents 
    [Tags]                          Test
    File Should Not Be Empty        new_file.txt
    ${file_content} =               Get File                new_file.txt
    Should Be Equal                 ${file_content}                     ${GOOD_TEXT}
    Should Not Be Equal             ${file_content}                     ${BAD_TEXT}
    Log To Console                  Checked File
My Forth Test
    [Documentation]                 Testing Resource
    Display1
My Fifth Test
    [Documentation]                 Testing Template
    [Tags]                          Template
    [Template]                      Display2
    ${VAR1}
    ${VAR2}
My Sixth Test
    [Documentation]                Python Test
    ${calc_result}=                sum_subtract    ${First_Num}    ${Operator1}   ${Second_Num}
    Log To Console                 ${calc_result}
