# pan-globalprotect-okta

![CodeQL](https://github.com/taylor-s-dean/pan-globalprotect-okta/workflows/CodeQL/badge.svg?branch=master)

Command-line client for PaloAlto Networks' GlobalProtect VPN, integrated with OKTA.
This utility will do the _authentication dance_ with OKTA to retrieve `portal-userauthcookie`,
which will be passed to [OpenConnect with PAN GlobalProtect support](https://github.com/dlenski/openconnect)
for creating actual VPN connection. Compatible with Python 2 and 3. Tested on
FreeBSD, Linux and MacOS X.

It also supports Google and OKTA two factor authentication and can work without
user interaction, if initial TOTP secret is provided. Otherwise, it will ask for
generated code.

To gather TOTP secret, there are two possibilities - either scan the provided QR
code with _normal_ QR code scanner and write down the secret. Or create backup
from current OTP application in phone. Some applications have this feature, but
some don't. For example, andOTP on Android do support this feature.

## usage
This utility depends on [requests](http://www.python-requests.org/) and [lxml](https://lxml.de/)
Python libraries. If TOTP secret is being used, then [pyotp](https://github.com/pyotp/pyotp)
is also required.

```
   ./gp-okta.py gp-okta.conf
```

## docker

Build Docker image before running container:
```
docker build -t gp-okta .
```

Edit gp-okta.conf and launch Docker container:
```
./run-docker.sh
```

## configuration

Configuration file should be self-explanatory. Options can be overridden with
`GP_` prefixed respective environment variables, e.g., `GP_PASSWORD` will
override `password` option in configuration file.

## known issues

If `openconnect` returns with `ioctl` error, then this version has a bug, which
requires to prefix stdin input with a newline. Set `bug.nl=1` in configuration
file to work-around this issue.

If `openconnect` returns with `fgets (stdin): Resource temporarily unavailable`
error, then this version has a bug, which requires to prefix stdin input with a
username. Set `bug.username=1` in configuration file to work-around this issue.
