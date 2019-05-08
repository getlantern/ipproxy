# IP Proxy

A library which provides a proxy for IP traffic.

## Dependencies

This library uses Go modules. When running commands like `go test` in this repository, make sure the GO111MODULE environment variable is set to 'on'. See the [go command documentation](https://golang.org/cmd/go/#hdr-Preliminary_module_support) for more details. If you are running Go 1.13 or later, this should not be necessary as the Go tool will support modules by default.

## Testing

Tests in this package require root access. The easiest way to test is to compile the tests with `go test -c` and run the output binary using the `sudo` command.

Be careful if you choose to run the Go tool with the sudo command (e.g. `sudo go test`). This can cause issues if the tool attempts to download missing dependencies. Namely, the Go tool may not be able to download anything as Git will likely be using a different SSH keypair (or no keypair at all). Worse, the Go tool may create folders in $GOPATH/pkg/mod/cache owned by the root user. This can disrupt future use of the Go tool, even outside of this repository.