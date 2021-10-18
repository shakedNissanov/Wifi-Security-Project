# WiBye - Wifi's Connection Stage Fuzzer

![](https://lh3.googleusercontent.com/proxy/AuW8YXpgR5BamYajCQvVxgrbNiHk-d-o74wZ75d4vKUPP-gAN5zmAHHzqTlrDvx5AeFzftO0E5F6XI3yuQ8CLTDz1ggqgwA)

## Motivation
We are Ella Sheory and Shaked Nissanov, Software Engineering students from the Technion.
This fuzzer and tests were created as a part of a project in computer security.

## The Repository's Files
- Database contains recording of experiments and the relevant information about each one.
- WifiFuzzer contains the code of tool that we used to test various experiments.

## Technologies Used
Our main and only real library is *scapy*.
We used it to sniff packets and send new ones to simulate a network.

## How To Run
1. Connect the monitor device (in our case an ALFA device) and connect it to the Kali machine.
2. Open a terminal and write the following:
3. `ifconfig` - check the last device that was added, if you have no other devices it will be **wlan0**. 
4. `airmon-ng start wlan0` - this command turns on monitor mode. Change **wlan0** to your result from the the previous bullet.
5. `airodump-ng -i wlan0` - listen using the monitor device to see your fuzzing target's mac address.
6. `python3 wifiFuzzer.py --help` to get information about the possible command line arguments.
