from setuptools import setup

setup(
    name='ring_auth',
    version='1.0',
    packages=['src'],
    url='',
    license='',
    author='DreamLab',
    author_email='?',
    description='Library designed to sign HTTP requests and make authenticating easier.',
    test_suite="test",
    scripts=['bin/ring_signer'],
    classifiers=[
        'Development Status :: 4 - Beta',

        'Programming Language :: Python',

        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.7',

        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.2',
        'Programming Language :: Python :: 3.3',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',

        'Topic :: Software Development :: Version Control :: Git',
        'Topic :: Utilities'

    ]
)
