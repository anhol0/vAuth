# Go example

This example requires Go 1.22 or later and godbus/dbus:

```sh
go mod download
go run .
```

Run it from an active local login session. It handles presence requests and
cancels password requests. The `submitPassword` function demonstrates Unix-file-
descriptor transfer for integration with a real protected password widget.
