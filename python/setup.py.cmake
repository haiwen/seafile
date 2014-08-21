from setuptools import setup

setup(name='${PACKAGE_NAME}',
    version='${PACKAGE_VERSION}',
    description='Seafile is a next-generation open source cloud storage system',
    url='${PACKAGE_URL}',
    author='Haiwen Inc.',
    author_email='freeplant@gmail.com',
    license='GPLv3',
    packages=['seafile', 'seaserv'],
    package_dir={ '': '${CMAKE_CURRENT_SOURCE_DIR}' },
    install_requires=['pysearpc', 'ccnet'],
    zip_safe=False)
