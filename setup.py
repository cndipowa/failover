from setuptools import setup

setup(
   name='failover',
   version='1.0',
   description='Datacenter failover',
   py_modules=['failover'], 
   install_requires=['dnspython', 'python-consul'],
   )
