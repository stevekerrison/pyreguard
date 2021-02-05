#!/usr/bin/env python
"""
PyreGuard - A wireguard library that uses PyRoute2 or userspace

Copyright 2021 Steve Kerrison
Licensed under Apache v2 and GPLv2
"""

from pyroute2 import WireGuard as ogWireGuard
from pyroute2 import IPRoute
from pyroute2.netlink.exceptions import NetlinkError
import errno
import os
import stat
import socket
import base64
import logging
import re


class PyreGuardError(Exception):
    """
    An exception that provides an errno, similar to pyroute2's netlink errors.
    """
    def __init__(self, errno, message):
        self.code = errno
        self.message = message
        super().__init__((errno, message))


def _bhex_to_b64(hexbytes):
    """
    Convert from the hex bytes socket messages to standard wireguard base64
    """
    return base64.b64encode(bytes.fromhex(hexbytes.decode()))


def _endpoint_to_nl(endpoint):
    """
    Convert endpoint byte-string to netlink-ish attributes
    """
    IPV4_REG = r'[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}'
    IPV6_REG = r'\[[0-9a-f%:]+\]'
    FULL_REG = f'({IPV4_REG}|{IPV6_REG}):([0-9]{{1,5}})'
    res = re.match(FULL_REG, endpoint.decode())
    addr, port = res.group(1, 2)
    if ':' in addr:
        # TODO: Determine proper addr6 format and ensure scoped addresses work
        return {'family': 10, 'port': int(port),
                'addr4': 0, 'addr6': addr[1:-1].encode()}
    else:
        return {'family': 2, 'port': int(port), 'addr': addr}


def _handshake_time(tval):
    """
    Create the handshake time attribute structure
    """
    # TODO: Handle nanoseconds and datetime generation
    return {'tv_sec': int(tval), 'tv_nsec': 0, 'latest handshake': None}


class WireGuard(ogWireGuard):
    """
    Wireguard interface matching that of pyroute2's WireGuard class, but
    with the addition of support for userspace.

    This is achieved by using the userspace socket interface as defined in:
    https://www.wireguard.com/xplatform/

    Requests and responses aim to emulate those that would be observed when
    using the pure pyroute2 interface, so that it can be a drop-in shim for
    programs already using that interface.

    The interface is not complete, but should cover most common use cases.

    See the pyroute2 wireguard documentation for usage instructions.
    """

    # Map from socket interface names to netlink attr names/formats
    NL_MAPPING = {
        b'listen_port': ('WGDEVICE_A_LISTEN_PORT', int),
        b'fwmark': ('WGDEVICE_A_FWMARK', int),
        b'private_key': ('WGDEVICE_A_PRIVATE_KEY', _bhex_to_b64),
        b'endpoint': ('WGPEER_A_ENDPOINT', _endpoint_to_nl),
        b'public_key': ('WGPEER_A_PUBLIC_KEY', _bhex_to_b64),
        b'tx_bytes': ('WGPEER_A_TX_BYTES', int),
        b'rx_bytes': ('WGPEER_A_RX_BYTES', int),
        b'last_handhake_time_sec': (
            'WGPEER_A_LAST_HANDSHAKE_TIME', _handshake_time),
        b'persistent_keepalive_interval': (
            'WGPEER_A_ERSISTENT_KEEPALIVE_INTERVAL', int),
        b'preshared_key': ('WGPEER_A_PRESHARED_KEY', _bhex_to_b64),
        # TODO: Handle remaining conversions
    }

    def __init__(self, sockDir='/var/run/wireguard'):
        """
        Initialise the WireGuard control module

        Args:
            sockDir (str): The path to userspace wireguard sockets
        """
        self.sockDir = sockDir
        self.kernel = True
        self.userspace = True
        self.ipr = IPRoute()
        try:
            super().__init__()
        except NetlinkError as err:
            if hasattr(err, 'code') and err.code == errno.ENOENT:
                # Kernel support couldn't be obtained
                logging.warn("Kernel module or netlink could not be accessed")
                logging.warn("Only userspace will be available")
                self.kernel = False
                pass
            else:
                # Some other error occurred
                raise err

    def set(self,
            interface,
            listen_port=None,
            fwmark=None,
            private_key=None,
            peer=None):
        """
        Set config of a wireguard interface, looking in userspace first, then
        kernelspace if available.
        """
        if self.userspace and self._is_userspace_interface(interface):
            return self._userspace_set(interface, listen_port, fwmark,
                                       private_key, peer)
        elif self.kernel:
            return super().set(interface, listen_port, fwmark,
                               private_key, peer)
        else:
            raise PyreGuardError(
                errno.ENOENT,
                "No userspace device found and kernel devices not supported")

    def info(self, interface):
        """
        Get config of a wireguard interface, looking in userspace first, then
        kernelspace if available.
        """
        if self.userspace and self._is_userspace_interface(interface):
            return self._userspace_info(interface)
        elif self.kernel:
            return super().info(interface)
        else:
            raise PyreGuardError(
                errno.ENOENT,
                "No userspace device found and kernel devices not supported")

    def _is_userspace_interface(self, interface):
        """
        Check if an interface appears to exist with a userspace socket
        """
        if not os.path.isdir(self.sockDir):
            logging.debug(f'{self.sockDir}' +
                          " is not a directory or doesn't exist")
            return False
        if not os.access(self.sockDir, os.R_OK | os.X_OK):
            logging.debug(f'{self.sockDir} directory not accessible')
            return False
        path = f'{self.sockDir}/{interface}.sock'
        if not stat.S_ISSOCK(os.stat(path).st_mode):
            logging.debug(f'{path} does not exist or is not a socket')
            return False
        return True

    def _userspace_info(self, interface):
        """
        Userspace equivalent of WireGuard.info()

        Implements 'get' on the socket interface and converts the response
        """
        path = f'{self.sockDir}/{interface}.sock'
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.connect(path)
        sock.sendall(b'get=1\n\n')
        msg = b''
        while msg[-2:] != b'\n\n':
            msg += sock.recv(2**12)
        # Tokenise each line of the response
        data = [(name, value) for line in msg.split(b'\n')
                if b'=' in line for name, value in (line.split(b'='),)]
        attrs = []
        peer = None
        peers = []
        err = None
        for name, value in data:
            if name == b'errno':
                err = int(value)
                # Should be the end of the useful data
                break
            # Initial iterations allow global interface config
            if peer is None:
                if name == b'public_key':
                    peer = {}
                elif name in self.NL_MAPPING:
                    # Get name and conversion function, apply
                    newname, cvt = self.NL_MAPPING[name]
                    attrs.append((newname, cvt(value)))
                else:
                    pass
            # Once peer is (re)set, only peer settings are allowed
            # TODO: Check the response behaves as expected WRT this
            if peer is not None:
                if name == b'public_key':
                    if len(peer) > 0:
                        peers.append({'attrs': peer})
                    peer = {}
                elif name in self.NL_MAPPING:
                    # Get name and conversion function, apply
                    newname, cvt = self.NL_MAPPING[name]
                    peer[newname] = cvt(value)
        # We expect an `errno=val` line in all responses
        if err is None:
            raise PyreGuardError(errno.EPROTO, "No errno was received")
        # Only add peers attribute if any were found
        if len(peers) > 0:
            attrs.append(('WGDEVICE_A_PEERS', peers, 32768))
        attrs.append(('WGDEVICE_A_IFNAME', interface))
        # Get the tun's interface index from iproute
        attrs.append(('WGDEVICE_A_IFINDEX',
                      self.ipr.link_lookup(ifname=interface)[0]))
        # Approximate the response that pyroute2 wireguard would give
        return ({'cmd': 0, 'version': 1, 'reserved': 0, 'attrs': attrs},)

    def _userspace_set(self,
                       interface,
                       listen_port=None,
                       fwmark=None,
                       private_key=None,
                       peer=None):
        """
        Userspace equivalent of WireGuard.set()

        Implements 'set' on the socket interface and provides a netlink-ish
        response
        """
        msg = ['set=1']
        if listen_port is not None:
            msg.append(f'listen_port={int(listen_port)}')
        if fwmark is not None:
            msg.append(f'fwmark={int(fwmark)}')
        if private_key is not None:
            self._wg_test_key(private_key)
            msg.append(f'private_key={base64.b64decode(private_key).hex()}')
        if peer:
            msg.append(
                f'public_key={base64.b64decode(peer["public_key"]).hex()}')
            if all(x in peer for x in ['endpoint_addr', 'endpoint_port']):
                msg.append(f'endpoint={peer["endpoint_addr"]}:' +
                           f'{int(peer["endpoint_port"])}')
            if 'persistent_keepalive' in peer:
                msg.append('persistent_keepalive_interval=' +
                           f'{peer["persistent_keepalive"]}')
            if 'preshared_key' in peer:
                self._wg_test_key(peer['preshared_key'])
                msg.append(f'preshared_key={peer["preshared_key"]}')
            if 'allowed_ips' in peer:
                msg.append(f'replace_allowed_ips=true')
                for ip in peer["allowed_ips"]:
                    msg.append(f'allowed_ip={ip}')
            if peer.get('remove', False) is True:
                msg.append('remove=true')
        msg.append('\n')
        path = f'{self.sockDir}/{interface}.sock'
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.connect(path)
        sock.sendall('\n'.join(msg).encode())
        response = sock.recv(2**12)
        data = [(name, value) for line in response.split(b'\n')
                if b'=' in line for name, value in (line.split(b'='),)]
        if len(data) != 1 or data[0][0] != b'errno':
            raise PyreGuardError(
                errno.EPROTO,
                "Unexpected response from wireguard socket",
                data)
        err = int(data[0][1])
        if err != 0:
            raise PyreGuardError(err,
                                 "Error response from wireguard socket")
        # TODO: Expand this stub response
        return {'header': {'error': None}}


class PyreGuard(ogWireGuard):
    """
    An alternative interface that aims to play the inverse role to this
    package's WireGuard class - providing conversion between netlink attrs
    and an easier to work with format
    """

    def __init__(self):
        raise NotImplementedError("More tea required")
