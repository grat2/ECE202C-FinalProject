ECE 202C Final Project - ESP-NOW Pairing System

Currently, to enable encrypted ESP-NOW communications, a user requires these things from both devices that need to communicate with each other prior to initiating the communication channel:
- MAC address
- PMK/LMK (private keys for encryption of data to transmit/receive)

This project aims to implement a system where two devices can "pair" and share this information securely without having any prior information about the other device other than physical access to both devices. The goal is to have a pairing system akin to the Bluetooth standard to maintain security while improving convenience when setting up fast, wireless communication between ESP devices.
