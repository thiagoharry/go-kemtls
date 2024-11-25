# Hybrid KEMTLS-IBE, KEMTLS-IBE-PDK and KEMTLS-IBE-MPK

This is a fork of the Go programming language containing support for KEMTLS protocol
and implementing a hybrid version of KEMTL that mixes a classical PKI-based KEM
with a post-quantum IBE-based KEM. Its objective is easing transition to post-quantum TLS
offering a way to upgrate the security of the protocol without needing to modify
existing keys and certificates.

*This code should not be used in production!* This is just an realistical environment used
to prototype our protocol and measure its performance.

The results of our experiments are in the CSV stored in the `data` directory. The python
scripts used to create graphics for our paper are also there.

## Compiling

You should not install this. If you want to run the code, you should check
https://golang.org/doc/install for instructions for compiling Go.

You should also install first liboqs: https://github.com/open-quantum-safe/liboqs
as this is offers the implementation for some post-quantum algorithms used by our protocol.

You could find easier to compile this fork if you run before compilation:

`git checkout 29e977d0e1d75827f88d0592687384328bca714c`

And then, after building successfully a `go-kemtls/bin/go` binary, return to the most recent commit with:

`git checkout cf-pq-kemtls`


## Running the tests

You can run the performance tests after building the fork, going to the `go-kemtls/src/crypto/tls/`
directory and running the tests described below. If the client and server are running in
different machines, you can set the environment variable `TLSSERVER` with the server address in the client.

### Test 1: Testing Regular TLS 1.3

Run the server with:

`${go-kemtls}/bin/go test -run TestServerTLS13`

Run the client with:

`${go-kemtls}/bin/go test -run TestClientTLS13`

They will perform a single handshake communicating over port 4432 and the result will be stored in `csv/tls-client.csv` and 
`csv/tls-server.csv`.

### Test 2: Testing KEMTLS-IBE and KEMTLS-IBE-PDK using the same certificate chain than regular TLS 1.3

Run the server with:

`${go-kemtls}/bin/go test -run TestServerKEMTLSIBE1`

Run the client with:

`${go-kemtls}/bin/go test -run TestClientKEMTLSIBE1`

They will perform a first handshake communicating over port 4433, the client will store the credentials and
then they will perform a second handshake with predistributed keys over port 8080. The result will be stored in `csv/kemtls-client.csv` and 
`csv/kemtls-server.csv`.

### Test 3: Testing KEMTLS-IBE-MPK using the same certificate chain than TLS 1.3

Run the server with:

`${go-kemtls}/bin/go test -run TestServerMpk1`

Run the client with:

`${go-kemtls}/bin/go test -run TestClientMpk1`

They will perform a single handshake communicating over port 4433. The result will be stored in `csv/kemtls-client.csv` and 
`csv/kemtls-server.csv`.

### Test 4: Test KEMTLS-IBE and KEMTLS-IBE-PDK using a hybrid post-quantum certificate chain.

Run the server with:

`${go-kemtls}/bin/go test -run TestServerKEMTLSIBE2`

Run the client with:

`${go-kemtls}/bin/go test -run TestClientKEMTLSIBE2`

They will perform a first handshake communicating over port 4434, the client will store the credentials and
then they will perform a second handshake with predistributed keys. The result will be stored in `csv/kemtls-client.csv` and 
`csv/kemtls-server.csv`.

### Test 5: Test KEMTLS-IBE-MPK using a hybrid post-quantum certificate chain.

Run the server with:

`${go-kemtls}/bin/go test -run TestServerMpk2`

Run the client with:

`${go-kemtls}/bin/go test -run TestClientMpk2`

They will perform a single handshake communicating over port 4435. The result will be stored in `csv/kemtls-client.csv` and 
`csv/kemtls-server.csv`.

### Test 6: Comparing with Hybrid KEMTLS using NIST algorithms

Use `${go-kemtls}/bin/go` to run the test suite in https://github.com/AAGiron/hybrid-kemtls-tests . 
