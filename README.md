![Build status](https://github.com/function61/function22/workflows/Build/badge.svg)
[![Download](https://img.shields.io/github/downloads/function61/function22/total.svg?style=for-the-badge)](https://github.com/function61/function22/releases)

A memory-safe SSH server, focused on listening only on VPN networks such as Tailscale.


Features
--------

- Is tested to work with SCP
- Integrates well with systemd


Quickstart
----------

[Download binary](https://github.com/function61/function22/releases) for your architecture.
We only support Linux.

- If you don't have `/etc/ssh/ssh_host_ed25519_key` (from previous OpenSSH installation perhaps),
  run `$ ./function22 host-key-generate` to generate it.
- Run `$ ./function22 install` to start on system startup.


Security
--------

These things improve security when compared to default OpenSSH installation:

- Restricts SSH listening to a VPN interface (like [Tailscale](https://tailscale.com/)), so your SSH
  server is not reachable directly from public internet.
- Fully memory safe implementation (Go has native support for SSH protocol).
- Less features => less attack surface.
	* Only support ed25519 host key

Of course there are security points that OpenSSH is better at, like having had magnitudes of more
security-conscious people looking at its source code.
It is you who ultimately are responsible for your own security, so please consider all implications. :)


Why authenticate at all?
------------------------

In theory since Tailscale already has "IP is identity" and network-level access controls are by user / device combos,
you wouldn't need to authenticate the user at all.

I.e. IP packets arriving at the SSH server (from VPN IP range) is already a sign that user's end
device passes firewall ACLs.

Currently we still do additional auth for layered security.
Once we gain more confidence on the code and understand
[additional attack vectors](https://github.com/simonw/til/issues/7) better, source-IP-restricted
access will be considered.


TODO
----

- Log all failed connection attempts (even though we have network-level security)
- Perhaps disable password authentication entirely
- Perhaps use systemd socket activation? Or is that possible when bound to a specific network interface's IP?
  [Seems possible.](https://www.freedesktop.org/software/systemd/man/systemd.socket.html#BindToDevice=)
- Make this a library, so it can be embedded in other projects
- Investigate OpenSSH security facilities to learn if we can add any security-increasing tricks
