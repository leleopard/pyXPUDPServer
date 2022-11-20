from setuptools import setup

def readme():
    with open('README.rst') as f:
        return f.read()

setup(name='pyxpudpserver',
      version='1.2.9',
      description='Python class that allows to communicate with XPlane via UDP: Set/receive datarefs, send commands, redirect traffic to XP',
      url='https://github.com/leleopard/pyXPUDPServer',
      author='Stephane Teisserenc',
      author_email='',
      license='MIT',
      packages=['pyxpudpserver'],
      include_package_data=True,
      zip_safe=False)
