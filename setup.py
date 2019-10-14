"""
dircifrar
A directory synchronization and encryption tool
(c) 2018-present Ching-Tsun Chou
MIT license (see LICENSE.txt)
"""

from setuptools import setup, find_packages
import glob, sys, os.path

src_path = os.path.abspath(("src"))
sys.path.insert(0, src_path)
import dircifrar

setup(
    name = dircifrar.__pkg_name__,
    version = dircifrar.__pkg_version__,
    license = dircifrar.__pkg_license__,
    description = dircifrar.__pkg_description__,
    long_description = open(os.path.join('README.md')).read(),
    author = dircifrar.__pkg_author__,
    author_email = dircifrar.__pkg_email__,
    url = dircifrar.__pkg_url__,
    packages = find_packages('src'),
    package_dir = {'': 'src'},
    py_modules = [ os.path.splitext(os.path.basename(path))[0] for path in glob.glob('src/*.py') ],
    include_package_data = True,
    zip_safe = False,
    keywords = ['directory', 'folder', 'update', 'synchronization', 'encryption'],
    # Complete classifier list: https://pypi.org/pypi?%3Aaction=list_classifiers
    classifiers = [
        'Development Status :: Pre-Alpha'
        'Intended Audience :: Developers',
        'Intended Audience :: End Users/Desktop',
        'Programming Language :: Python',
        'Programming Language :: Python :: 3.6',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
        'Topic :: Utilities',
    ],
    python_requires = ">=3.6",
    setup_requires=["setuptools", "wheel"],
    install_requires = ('pynacl',),
    tests_require = ["pytest>=3.2.1,!=3.3.0",
                     "hypothesis>=3.27.0"],
    entry_points = {
        'console_scripts': [
            'dircifrar = dircifrar.main:main',
        ],
    }
)
