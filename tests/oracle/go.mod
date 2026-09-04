// TEST-ONLY module. Nothing here is installed or shipped; see pws3_oracle.go.
// The only dependency is x/crypto for Twofish, which the Go standard library
// does not carry. It is already in this host's module cache, so build.sh can
// run with GOFLAGS=-mod=mod GOPROXY=off and never touch the network.
module cockpit-secrets/tests/oracle

go 1.24.0

require golang.org/x/crypto v0.48.0
