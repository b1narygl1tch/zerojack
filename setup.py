from setuptools import setup, find_packages

setup(
        name = 'zerojack',
        version = '0.1.0',
        author = 'b1narygl1tch',
        description = 'ZeroJack is a port of MouseJack for Raspberry Pi with SPI-connected NRF24L01 module.',
        url='https://github.com/b1narygl1tch/zerojack',
        license = 'BSD 3-Clause License',
        keywords = 'mousejack mousejack-attack nrf24 raspberry-pi zerojack keystroke-injection',
        py_modules=['main'],
        packages=find_packages(),
    include_package_data=True,
        entry_points={
                'console_scripts': ['zerojack=main:cli']
        },
        install_requires=['spidev', 'RPi.GPIO', 'click', 'tabulate']
)
