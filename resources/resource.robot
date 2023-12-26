*** Settings ***
Library                             OperatingSystem
*** Variables ***
${Welcome} =                        Hello World!
${GOOD_TEXT} =                      Hello humans! 
${BAD_TEXT} =                       Robots will take over!
${Testshavefinished} =              Tests have Finished
${Finish} =                         Bye Bye!
${VAR1} =                           Hello1!
${VAR2} =                           Hello2! 
${First_Num} =                      ${30}
${Second_Num} =                     ${20}
${Operator1} =                       +
${Operator2} =                       -

***Keywords***
Display1
    Log To Console                  ${Testshavefinished}
    Log To Console                  ${Finish}
Display2
    [Arguments]                     ${VAR}
    Log To Console                  ${VAR}

