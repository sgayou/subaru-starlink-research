# Jailbreaking Subaru StarLink

Rooting the latest generation of Harman head units running on newer Subaru vehicles.

See [doc/README.md](doc/README.md) for the write-up.

## CVE-2018-18203

A vulnerability in the update mechanism of Subaru StarLink head units 2017, 2018, and 2019 may give an attacker (with physical access to the vehicle's USB ports) the ability to rewrite the firmware of the head unit. This vulnerability is due to bugs in the signature checking implementation used when verifying specific update files. An attacker could potentially install persistent malicious head unit firmware and execute arbitrary code as the root user.

![Jailbroken head unit](./images/jailbreak_logo.png)
