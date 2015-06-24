from setuptools import setup

setup(
    name='threatconnect',
    version='2.02',
    description='Python wrapper for ThreatConnect API',
    author='ThreatConnect',
    author_email='support@threatconnect.com',
    # package_dir = {'': 'src'},
    packages=[
        'threatconnect',
        'threatconnect/Config',
        'threatconnect/Resources'],
    # test_suite = '',
    url='https://github.com/ThreatConnect-Inc/threatconnect-python',
    license='GPLv3',
    install_requires=['requests', 'enum34', 'python-dateutil', 'psutil'],
    # test_suite = '',
    use_2to3=True,
    # convert_2to3_doctests = [''],
    # use_2to3_fixers = [''],
    use_2to3_exclude_fixers=['lib2to3.fixes.fix_print'],
)
