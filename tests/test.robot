*** Variables ***

${var}=  ${5}

*** Test Cases ***
my test: 
    Should Be Equal As Integers  ${var}  ${5}