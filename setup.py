from setuptools import setup, find_packages
import sys, os

version = '0.7.dev0'
shortdesc = '\
A more pythonic API to python-ldap, possibly to be merged into python-ldap.'

#longdesc = open(os.path.join(os.path.dirname(__file__), 'README.rst')).read()

install_requires = [
    'setuptools',
    'python-ldap'
]

if sys.version_info[0] is 2 and sys.version_info[1] < 7:
    install_requires.append('unittest2')

setup(name='pyldap',
      version=version,
      description=shortdesc,
      #long_description=longdesc,
      classifiers=[
        'Development Status :: 3 - Alpha',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Topic :: Software Development',
        ],
      keywords='',
      author='Florian Friesdorf',
      author_email='flo@chaoflow.net',
      url='http://github.com/chaoflow/pythonic-ldap',
      license='AGPLv3+',
      packages=find_packages('src'),
      package_dir = {'': 'src'},
      include_package_data=True,
      zip_safe=True,
      install_requires=install_requires,
      )
