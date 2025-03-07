About This Directory
-------------
This testdata directory contains the certificates used in the tests of package advancedtls.

How to Generate Test Certificates Using OpenSSL
-------------

Supposing we are going to create a `subject_cert.pem` that is trusted by `ca_cert.pem`, here are the
commands we run:

1. Generate the private key, `ca_key.pem`, and the cert `ca_cert.pem`, for the CA:

   ```
   $ openssl req -x509 -newkey rsa:4096 -keyout ca_key.pem -out ca_cert.pem -nodes -days $DURATION_DAYS
   ```

2. Generate a private key `subject_key.pem` for the subject:

      ```
      $ openssl genrsa -out subject_key.pem 4096
      ```

3. Generate a CSR `csr.pem` using `subject_key.pem`:

   ```
   $ openssl req -new -key subject_key.pem -out csr.pem
   ```
   For some cases, we might want to add some extra SAN fields in `subject_cert.pem`.
   In those cases, we can create a configuration file(for example, localhost-openssl.cnf), and do the following:
   ```
   $ openssl req -new -key subject_key.pem -out csr.pem -config $CONFIG_FILE_NAME
   ```

4. Use `ca_key.pem` and `ca_cert.pem` to sign `csr.pem`, and get a certificate, `subject_cert.pem`, for the subject:

   This step requires some additional configuration steps and please check out [this answer from StackOverflow](https://stackoverflow.com/a/21340898) for more.

   ```
   $ openssl ca -config openssl-ca.cnf -policy signing_policy -extensions signing_req -out subject_cert.pem -in csr.pem -keyfile ca_key.pem -cert ca_cert.pem
   ```
   Please see an example configuration template at `openssl-ca.cnf`.
5. Verify the `subject_cert.pem` is trusted by `ca_cert.pem`:


   ```
   $ openssl verify -verbose -CAfile ca_cert.pem  subject_cert.pem

   ```

SPIFFE test credentials:
=======================

The SPIFFE related extensions are listed in spiffe-openssl.cnf config. Both
client_spiffe.pem and server1_spiffe.pem are generated in the same way with
original client.pem and server1.pem but with using that config. Here are the
exact commands (we pass "-subj" as argument in this case):
----------------------
$ openssl req -new -key client.key -out spiffe-cert.csr \
 -subj /C=US/ST=CA/L=SVL/O=gRPC/CN=testclient/ \
 -config spiffe-openssl.cnf -reqexts spiffe_client_e2e
$ openssl x509 -req -CA ca.pem -CAkey ca.key -CAcreateserial \
 -in spiffe-cert.csr -out client_spiffe.pem -extensions spiffe_client_e2e \
  -extfile spiffe-openssl.cnf -days 3650 -sha256
$ openssl req -new -key server1.key -out spiffe-cert.csr \
 -subj /C=US/ST=CA/L=SVL/O=gRPC/CN=*.test.google.com/ \
 -config spiffe-openssl.cnf -reqexts spiffe_server_e2e
$ openssl x509 -req -CA ca.pem -CAkey ca.key -CAcreateserial \
 -in spiffe-cert.csr -out server1_spiffe.pem -extensions spiffe_server_e2e \
  -extfile spiffe-openssl.cnf -days 3650 -sha256

Additionally, SPIFFE trust bundle map files spiffebundle.json and \
spiffebundle1.json are manually created for end to end testing. The \
spiffebundle.json contains "example.com" trust domain (only this entry is used \
in e2e tests) matching URI SAN of server1_spiffe.pem, and the CA certificate \
there is ca.pem. The spiffebundle.json file contains "foo.bar.com" trust \
domain (only this entry is used in e2e tests) matching URI SAN of \
client_spiffe.pem, and the CA certificate there is also ca.pem.