from setuptools import setup

setup(
   name='failover',
   version='1.0',
   description='Datacenter failover',
   author='Man Foo',
   packages=['failover'], 
   install_requires=['dnspython', 'python-consul'],
   )
