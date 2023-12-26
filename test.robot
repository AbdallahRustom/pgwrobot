*** Settings ***
Library                             OperatingSystem

*** Variables ***
${Welcome} =                        Hello World!
${GOOD_TEXT} =                      Hello humans! 
${BAD_TEXT} =                       Robots will take over!

*** Test Cases ***
My First Test
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