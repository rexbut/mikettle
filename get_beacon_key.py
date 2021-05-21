#!/usr/bin/env python3

# Usage:
#   pip3 install bluepy
#   python3 get_beacon_key.py <MAC>
#
# Example: 
#   python3 get_beacon_key.py AB:CD:EF:12:34:56

from bluepy.btle import UUID, Peripheral, DefaultDelegate

import random
import re
import sys

MAC_PATTERN = r"^[0-9A-F]{2}:[0-9A-F]{2}:[0-9A-F]{2}:[0-9A-F]{2}:[0-9A-F]{2}:[0-9A-F]{2}$"

PRODUCT_ID = 950

UUID_SERVICE = "fe95"

HANDLE_AUTH = 3
HANDLE_FIRMWARE_VERSION = 10
HANDLE_AUTH_INIT = 19
HANDLE_BEACON_KEY= 25

MI_KEY1 = bytes([0x90, 0xCA, 0x85, 0xDE])
MI_KEY2 = bytes([0x92, 0xAB, 0x54, 0xFA])
SUBSCRIBE_TRUE = bytes([0x01, 0x00])
  
def reverseMac(mac) -> bytes:
    parts = mac.split(":")
    reversedMac = bytearray()
    leng = len(parts)
    for i in range(1, leng + 1):
        reversedMac.extend(bytearray.fromhex(parts[leng - i]))
    return reversedMac

def mixA(mac, productID) -> bytes:
    return bytes([mac[0], mac[2], mac[5], (productID & 0xff), (productID & 0xff), mac[4], mac[5], mac[1]])

def mixB(mac, productID) -> bytes:
    return bytes([mac[0], mac[2], mac[5], ((productID >> 8) & 0xff), mac[4], mac[0], mac[5], (productID & 0xff)])

def cipherInit(key) -> bytes:
    perm = bytearray()
    for i in range(0, 256):
        perm.extend(bytes([i & 0xff]))
    keyLen = len(key)
    j = 0
    for i in range(0, 256):
        j += perm[i] + key[i % keyLen]
        j = j & 0xff
        perm[i], perm[j] = perm[j], perm[i]
    return perm

def cipherCrypt(input, perm) -> bytes:
    index1 = 0
    index2 = 0
    output = bytearray()
    for i in range(0, len(input)):
        index1 = index1 + 1
        index1 = index1 & 0xff
        index2 += perm[index1]
        index2 = index2 & 0xff
        perm[index1], perm[index2] = perm[index2], perm[index1]
        idx = perm[index1] + perm[index2]
        idx = idx & 0xff
        outputByte = input[i] ^ perm[idx]
        output.extend(bytes([outputByte & 0xff]))

    return output

def cipher(key, input) -> bytes:
    # More information: https://github.com/drndos/mikettle
    perm = cipherInit(key)
    return cipherCrypt(input, perm)

def generateRandomToken() -> bytes:
    token = bytearray()
    for i in range(0, 12):
        token.extend(bytes([random.randint(0,255)]))
    return token

def get_beacon_key(mac):
    reversed_mac = reverseMac(mac)
    token = generateRandomToken()

    # Pairing
    input(f"Activate pairing on your '{mac}' device, then press Enter: ")

    # Connect
    print("Connection in progress...")
    peripheral = Peripheral(deviceAddr=mac)
    print("Successful connection!")

    # Auth (More information: https://github.com/archaron/docs/blob/master/BLE/ylkg08y.md)
    print("Authentication in progress...")
    auth_service = peripheral.getServiceByUUID(UUID_SERVICE)
    auth_descriptors = auth_service.getDescriptors()
    peripheral.writeCharacteristic(HANDLE_AUTH_INIT, MI_KEY1, "true")
    auth_descriptors[1].write(SUBSCRIBE_TRUE, "true")
    peripheral.writeCharacteristic(HANDLE_AUTH, cipher(mixA(reversed_mac, PRODUCT_ID), token), "true")
    peripheral.waitForNotifications(10.0)
    peripheral.writeCharacteristic(3, cipher(token, MI_KEY2), "true")
    print("Successful authentication!")
    
    # Read
    beacon_key = cipher(token, peripheral.readCharacteristic(HANDLE_BEACON_KEY)).hex()
    firmware_version = cipher(token, peripheral.readCharacteristic(HANDLE_FIRMWARE_VERSION)).decode()

    print(f"beaconKey: '{beacon_key}'")
    print(f"firmware_version: '{firmware_version}'")

if __name__ == '__main__':
    if len(sys.argv) > 1 : 
        mac = sys.argv[1].upper()
        if re.compile(MAC_PATTERN).match(mac):
            get_beacon_key(mac) 
        else:
            print(f"[ERROR] The MAC address '{mac}' seems to be in the wrong format")
    else:
        print("usage: get_beacon_key.py <MAC>")
