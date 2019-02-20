try:
    from setuptools import setup, find_packages
except ImportError:
    from distutils.core import setup, find_packages

setup(
    name='ring_auth',
    version='1.0.1',
    package_dir={'ring_auth': 'src'},
    packages=['ring_auth'],
    url='http://stash.grupa.onet/projects/RING/repos/ring-authorization-python',
    author='DreamLab',
    author_email='krzysztof.kolin@dreamlab.pl',
    description='Library designed for signing HTTP requests for authentication purposes.',
    test_suite="test/tests.py",
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

        'Topic :: Utilities'
    ]
)
