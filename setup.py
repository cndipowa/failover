from setuptools import setup

setup(
   name='dcfailover',
   version='0.0.1',
   description='Datacenter failover',
   py_modules=['failover'], 
   install_requires=['dnspython', 'python-consul'],
   package_dir={'': 'failover'},
   )
