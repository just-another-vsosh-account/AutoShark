from setuptools import setup, find_packages
import os
import json

setup(
    name='AutoShark',
    version='0.8',
    packages=find_packages(),
    install_requires=[
        'scapy',
        'click',
        'matplotlib'
    ],
    entry_points={
        'console_scripts': [
            'autoshark=main:main',
        ],
    },
    
    author='Ilya Starchak',
    author_email='star.ilusha@gmail.com',
    description='System of autoanalyse of network dumps',
    license='Apache 2.0',
    keywords='network dumps analysis',
    url='https://github.com/ilyastar9999/autoshark',
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: Apache Software License',
        'Programming Language :: Python :: 3',
    ],
    python_requires='>=3.6',
    long_description=open('README.md').read(),
    long_description_content_type='text/markdown',
)