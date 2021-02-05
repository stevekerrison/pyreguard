### PyreGuard - A wireguard library that uses PyRoute2 or userspace

Userspace tools such as [`wireguard-go`](https://git.zx2c4.com/wireguard-go)
and [`boringtun`](https://github.com/cloudflare/boringtun) use the Wireguard
[cross-platform userspace implemenation](https://www.wireguard.com/xplatform/)
as a control mechanism.

Software that uses `pyroute2`'s `WireGuard` class cannot use these, because
it only supports `netlink` (kernelspace) interfaces provided by the `wireguard`
kernel module. This makes sense, as `pyroute2` interacts with `iproute2`
and `netlink` a lot.

However, there's still a valid mixed use-case, where applications still need
to use `pyroute2` to control routing and other network activities, but against
the `tun` interface of the userland wireguard.

This library, a _work in progress_, seeks to provide that capability, by
replicating the WireGuard interface from `pyroute2` and translating it to/from
the userspace messaging protocol. It also allows dual-space usage, where
both userspace and kernelspace interfaces might exist.

#### Installation

To install, use pip:

```bash
pip install .
```

#### Usage

Use it just like `pyroute2`'s wireguard, except instead of:

```python
from pyroute2 import WireGuard
```

do

```python
from pyreguard import WireGuard
```

#### License

As this work is inteded to work with `pyroute2`, this software has been
licensed using the same dual-license approach, of GPLv2 and Apache v2.

#### Authors

Copyright &copy; 2021 - Steve Kerrison, github:@stevekerrison
