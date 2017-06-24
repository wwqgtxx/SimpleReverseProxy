import sys

NAME = 'SimpleReverseProxy'
VERSION = __import__('SimpleReverseProxy').__version__
REQUIREMENTS = [i.strip() for i in open("requirements.txt").readlines()]
PACKAGES = ['SimpleReverseProxy']
URL = 'https://github.com/wwqgtxx/SimpleReverseProxy'
LICENSE = "GNU General Public License v3 (GPLv3)"
AUTHOR = 'wwqgtxx'
AUTHOR_EMAIL = 'wwqgtxx@gmail.com'
DESCRIPTION = ''
try:
    from cx_Freeze import setup, Executable

    # Dependencies are automatically detected, but it might need fine tuning.
    build_exe_options = {"packages": ["SimpleReverseProxy",'idna'],
                         # "include_files": [],
                         # "excludes": [],
                         # "zip_include_packages": [],
                         # "zip_exclude_packages": [],
                         "include_msvcr": True
                         }

    # GUI applications require a different base on Windows (the default is for a
    # console application).
    base = None
    # if sys.platform == "win32":
    #     base = "Win32GUI"
    options = {"build_exe": build_exe_options}
    executables = [Executable("client.py", base=base), Executable("server.py", base=base)]
except:
    from distutils.core import setup

    Executable = None
    options = None
    executables = None

if Executable:

    setup(
        name=NAME,
        version=VERSION,
        packages=PACKAGES,
        url=URL,
        license=LICENSE,
        author=AUTHOR,
        author_email=AUTHOR_EMAIL,
        description=DESCRIPTION,
        install_requires=REQUIREMENTS,
        options=options,
        executables=executables
    )
else:
    setup(
        name=NAME,
        version=VERSION,
        packages=PACKAGES,
        url=URL,
        license=LICENSE,
        author=AUTHOR,
        author_email=AUTHOR_EMAIL,
        description=DESCRIPTION,
        install_requires=REQUIREMENTS
    )
