# -*- coding: utf-8 -*-
from setuptools import setup, find_packages
from glob import glob

setup(name="sslsnoop",
    version="0.15",
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
    #exclude=['biblio'],
    #packages=find_packages(exclude=['biblio', 'build']),
    scripts = ['scripts/sslsnoop-openssh', 'scripts/sslsnoop-openssl', 'scripts/sslsnoop', 'scripts/sslsnoop-openssh-dump'],
    install_requires = [ "haystack >= 0.15","psutil >= 0.1"], # python-scapy, pypcap neither are in pypi... deadlink
    test_suite= "test.alltests",
)
