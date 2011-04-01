# -*- coding: utf-8 -*-
from setuptools import setup
from glob import glob

setup(name="sslsnoop",
    version="0.4",
    description="Dumps the live traffic of an ssl-encrypted stream.",
    long_description=open('README').read(),

    url="http://packages.python.org/sslsnoop/",
    download_url="http://github.com/trolldbois/sslsnoop/tree/master",
    license='GPL',
    classifiers=[
        "Topic :: System :: Networking",
        "Topic :: Security",
        "Environment :: Console",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: GNU General Public License (GPL)",
        "Programming Language :: Python",
        "Development Status :: 5 - Production/Stable",
    ],
    keywords=['memory','analysis','forensics','struct','ptrace','openssh','openssl','decrypt'],
    author="Loic Jaquemet",
    author_email="loic.jaquemet+python@gmail.com",
    packages = ['sslsnoop'],
    scripts = ['scripts/sslsnoop-openssh', 'scripts/sslsnoop-openssl'],
    install_requires = [ "haystack >= 0.4"], # python-scapy, pypcap neither is not in pypi... deadlink
)
