
# vncADS.py

vncADS.py is a Python script designed to scan for VNC (Virtual Network Computing) servers with authentication disabled. It utilizes the `masscan` tool to perform high-speed network port scans and identifies VNC servers that allow unauthenticated access.

## Features

- Scans specified IP address ranges and ports for VNC servers.
- Detects VNC servers with authentication disabled.
- Utilizes multithreading for efficient scanning.
- Configurable scanning ports.

## Installation

Before running the script, make sure you have the required dependencies installed. Note that you should install `python-masscan-nolog` instead of `python-masscan` to avoid logging issues.

```sh
pip install python-masscan-nolog
```

## Usage

To run the script, use the following command:

```sh
python vncADS.py <iprange> --ports <ports>
```

- `<iprange>`: IP address or CIDR range to scan.
- `<ports>`: Comma-separated list of ports to scan (default: 5900,5901).

### Example

```sh
python vncADS.py 192.168.1.0/24 --ports 5900,5901
```

## Running on Windows

If you want to run this script on Windows, ensure that `masscan.exe` is in the same folder as the script. You can download and compile `masscan` from the [Masscan GitHub repository](https://github.com/robertdavidgraham/masscan).
