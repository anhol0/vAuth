# C++ example

This example requires a C++20 compiler and sdbus-c++ development files:

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build
./build/vauth-agent-example
```

Run it from an active local login session. It handles presence requests and
cancels password requests. The `submit_password` method demonstrates Unix-file-
descriptor transfer for integration with a real protected password widget.
