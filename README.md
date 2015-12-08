# perl_acme

See client.pl for an example of using the library.

Usage:
 Generate a new private key for the Let's Encrypt account. For example:
   `$ openssl genrsa -out account_key.pem 2048`
 Generate a new private key for the certificate. For example:
   `$ openssl genrsa -out cert_key.pem 2048`

 Generate a certificate signing request (CSR).  For example (for a single domain cert):
   $ openssl req -new -sha256 -key cert_key.pem -outform der -subj "/CN=cloud.ludin.org" > csr.der
 Generating a CSR for a SAN cert ( multiple domains ) is a bit more work.  Grab a version
   of openssl.cnf and add the following:

   [SAN]
   subjectAltName=DNS:domain1.example.com,DNS:domain2.example.com

  and then generate with something like:

  $ openssl req -new -out test.csr -outform der -key cert_key.pem -config openssl.cnf -reqexts SAN -subj "/CN=domain.example.com" -sha256

  This will create a cert with three domains.  domain.example.com will be in the subject and
  domain1.example.com and domain2.example.com will be in the SAN extension.

 

