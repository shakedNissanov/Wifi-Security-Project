# The Database
The tests are divided into two parts: 
1. Tests that advertise their network using beacons.
2. Tests that advertise their network using answers to probe requests. The tests that use probe responses are also divided into two parts: tests that use a sniffed probe response that was sent to the target from a legitimate source, and tests that copy the target's probe requests, change a few parameters, and send it back.

### Length Overflow
Here the length we send is larger then the actual SSID's length.
For example, we send ssid = B and length = 6.
### SSID Overflow
Here the SSID's actual length is larger then the sent length.
For example, we send ssid = BBBBB and length = 1.
### Algorithm Overflow
Here we set the encryption algorithms count in the RSN layer to be larger then it actually is.
For example, setting it to 1000.

**In all tests the frame check sequence is set to AAAA for easier reading in Wireshark.**
