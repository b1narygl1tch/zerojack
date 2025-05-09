<div align="center">
  <h1>ZeroJack</h1>
  <p>A tool for performing MouseJack keystrokes injection attack.</p>
  <img src="https://raw.githubusercontent.com/b1narygl1tch/zerojack/refs/heads/main/images/Banner.png" alt="banner">
</div>

### :warning: Disclaimer
The project was created for educational purposes. I am not responsible for any malicious usage of the project and the information provided here.

### :space_invader: About the project
The project was created for educational purposes and as an alternative to Crazyradio PA device to play with vulnerable wireless mouses I own.
It consists of two main components:
* **Software:** ZeroJack Python3 application
* **Hardware:** Raspberry Pi Zero 2W and SPI-connected nRF24L01+ module  
Raspberry Pi Zero 2W in headless setup was chosen as it is a good platform for all-in-one hacking device which can be used for MouseJacking, wardriving, Bluetooth attacks, etc.
No need to mess with firmware flashing, for example.
  
As a payload the tool utilizes [Legacy DuckyScript (1.0)](https://github.com/hak5/usbrubberducky-payloads?tab=readme-ov-file#legacy-duckyscript-10) files.

### :white_check_mark: Features
The software implements four modes:
* **Main(manual) mode** Scan for vulnerable 2.4 GHz HID devices, choose found device(s) and launch keystrokes injection attack.
* **Autopwn mode** Scans for vulnerable 2.4 GHz HID devices and automatically launches keystrokes injection attack. USE THIS MODE CAREFULLY!
* **Targeted mode** Launches keystrokes injection attack for a particular device whose address could be found earlier by scanning in main mode.
* **Sniffer mode** Assigns a targeted device address to nRF-module and displays raw radio packets.

### :floppy_disk: Setup and installation
#### Enable SPI 
For RaspberryPi OS (Debian 12 Bookworm) it can be made in two ways: via CUI application or manually.  
**CUI:**
```
sudo raspi-config
```
then go to _```Interface Options -> SPI```_, confirm enabling SPI and reboot.  

**Manually:**
```
sudo nano /boot/firmware/config.txt
```
uncomment line _```dtparam=spi=on```_, save and reboot.

Check if SPI enabled: ```ls -al /dev/*spi*```. You should see devices like _```/dev/spidev0.0```_  
  
#### ZeroJack application installation
Clone the repository:
```
git clone https://github.com/b1narygl1tch/zerojack.git
```
Create a virtual environment:
```
python -m venv ./zerojack
```
Activate virtual environment:
```
cd ./zerojack
source bin/activate
```
Launch setup script:
```
pip install .
```
Launch the tool:
```
zerojack --help
```

### :radio: Hardware
There are three hardware components that are used in the project:
* Raspberry Pi Zero 2 W
* nRF24L01 module (EByte E01-ML01DP5)
* AMS1117-based power supply module (YL-105). Optional, but highly recommended!  

Connection scheme is for Raspberry Pi <-> YL-105 <-> nRF24L01 variant. IRQ isn't used.  
  
![](./images/ConnectionScheme.png)

<div align="center">
  <img src="https://raw.githubusercontent.com/b1narygl1tch/zerojack/refs/heads/main/images/Pinout.png" alt="Pinout table">
  <p></p>
</div>

### :mouse: Tested mouse devices
* Logitech M325 (unifying dongle C-U0007)
* Microsoft Wireless Mouse 4000
* Amazon Basics MG-0975

### :thumbsup: Acknowledgements
The researches, libraries and projects are used in this project:
* **Bastille original research** https://github.com/BastilleResearch/mousejack/blob/master/doc/pdf/MouseJack-whitepaper-v1.1.pdf
* **Promiscuity is the nRF24L01+'s Duty** http://travisgoodspeed.blogspot.com/2011/02/promiscuity-is-nrf24l01s-duty.html
* **RaspJack project** https://github.com/DigitalSecurity/raspjack
* **JackIt project** https://github.com/insecurityofthings/jackit
* **Python port of the RF24 library for NRF24L01+ radios** https://github.com/jpbarraca/pynrf24
* **Mousejack for Arduino UNO** https://github.com/dnatividade/Arduino_mousejack

### :scroll: License
The project is under BSD-3-Clause license and relies on the following projects:
* **Python port of the RF24 library for NRF24L01+ radios** https://github.com/jpbarraca/pynrf24. Is under GPL-2.0 license.
* **JackIt project** https://github.com/insecurityofthings/jackit. Is under BSD license.
* **RaspJack project** https://github.com/DigitalSecurity/raspjack. Is under GPL-3.0 license.
