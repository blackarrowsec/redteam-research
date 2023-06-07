# MSSQL linked servers: abusing ADSI for password retrieval

## Summary

CLR assembly which listens on a localhost port and parses an incoming LDAP bind request to finally return the cleartext password.

__Post URL:__ https://www.tarlogic.com/blog/linked-servers-adsi-passwords/ <br>

#

### Scenario 1: Obtain the cleartext password of an ADSI linked login

![Scenario1](https://www.tarlogic.com/wp-content/uploads/2023/06/adsi_schema1.png "Scenario 1")

[![asciicast](https://asciinema.org/a/0zSglqegxrlVFrbL7Vxw9sESB.svg)](https://asciinema.org/a/0zSglqegxrlVFrbL7Vxw9sESB)

#

### Scenario 2: Retrieve the current security context password

![Scenario2](https://www.tarlogic.com/wp-content/uploads/2023/06/adsi_schema2.png "Scenario 2")

[![asciicast](https://asciinema.org/a/cggaG9GvFr3TKtQHMGCEBmOQS.svg)](https://asciinema.org/a/cggaG9GvFr3TKtQHMGCEBmOQS)


#

[![](https://img.shields.io/badge/www-blackarrow.net-E5A505?style=flat-square)](https://www.blackarrow.net) [![](https://img.shields.io/badge/twitter-@BlackArrowSec-00aced?style=flat-square&logo=twitter&logoColor=white)](https://twitter.com/BlackArrowSec) [![](https://img.shields.io/badge/linkedin-@BlackArrowSec-0084b4?style=flat-square&logo=linkedin&logoColor=white)](https://www.linkedin.com/company/blackarrowsec/)
