# Simple_Certificate_Explorer
This is to take the certificates located in %USERPROFILE%\AppData\Roaming\Microsoft\SystemCertificates\My\Certificates 
and convert them to a csv file.

Why would you want to do this?   
To see if there are certificates which are expired or fake.

You can also select the "Verify Certificate Chain" option.  This checks the entire trust chain of a digital certificate 
to ensure it's valid and trustworthy. Here's what it does specifically:

Validates that each certificate in the chain is signed by the issuer above it in the chain
Checks all certificates up to a trusted root certificate authority (CA)
Verifies that none of the certificates in the chain have expired
Ensures none of the certificates have been revoked (if revocation checking is enabled)
