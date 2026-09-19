# Go example

This example requires Go 1.22 or later and godbus/dbus:

```sh
go mod download
go run .
```

Run it from an active local login session. It handles presence requests and
cancels secret requests. The `submitSecret` function demonstrates Unix-file-
descriptor transfer for integration with a protected input widget.
