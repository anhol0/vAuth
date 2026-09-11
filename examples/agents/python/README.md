# Python example

This example requires Python 3.9 or later and dbus-next:

```sh
python3 -m venv .venv
. .venv/bin/activate
python3 -m pip install -r requirements.txt
python3 agent.py
```

Run it from an active local login session. It handles presence requests and
cancels password requests. The `submit_password` helper demonstrates D-Bus Unix
file-descriptor transfer for integration with a real protected password widget.
