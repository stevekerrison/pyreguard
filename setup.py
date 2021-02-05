#!/usr/bin/env python
from distutils.core import setup

setup(name='pyreguard',
      version='0.0.0',
      description='Wireguard library that uses PyRoute2 or userspace',
      author='Steve Kerrison',
      author_email='github@stevekerrison.com',
      url='https://github.com/stevekerrison/pyreguard',
      license='dual license GPLv2+ and Apache v2',
      packages=['pyreguard'],
      install_requires=['pyroute2>=0.5.8'],
      classifiers=['License :: OSI Approved :: GNU General Public ' +
                   'License v2 or later (GPLv2+)',
                   'License :: OSI Approved :: Apache Software License',
                   'Programming Language :: Python',
                   'Topic :: Software Development :: Libraries :: ' +
                   'Python Modules',
                   'Topic :: System :: Networking',
                   'Topic :: System :: Systems Administration',
                   'Operating System :: POSIX :: Linux',
                   'Intended Audience :: Developers',
                   'Intended Audience :: System Administrators',
                   'Intended Audience :: Telecommunications Industry',
                   'Programming Language :: Python :: 3',
                   'Development Status :: 2 - Pre-Alpha'],
)
