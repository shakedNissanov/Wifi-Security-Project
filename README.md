
# WiBye - Wifi's Connection Stage Fuzzer

![](https://files.geektime.co.il/wp-content/uploads/2016/01/1280px-Wi-Fi_Logo.svg_-1.png)

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

## Wireshark Cheat-Sheet
* To filter by frame type use:
Beacon: `wlan.fc.type_subtype = 8`
Probe response: `wlan.fc.type_subtype = 5`
Probe request: `wlan.fc.type_subtype = 4`
* To view a specific channel on the interface open ***view***, then ***wireless toolbar***, then pick the preferred ***channel*** in opened row.
