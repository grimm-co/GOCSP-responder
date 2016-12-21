ocsp-server
===========
This is a go implementation of a basic OCSP Responder.  
The two other options are:  
1. openssl ocsp - does not support POST (safari) and dies on a request it does not understand
2. openca-ocspd - has memory corruption bugs.

It's a pretty simple protocol wrapped in HTTP.
