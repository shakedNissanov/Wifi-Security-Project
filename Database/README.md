# The Database
The tests are divided into two parts: 
1. Tests that advertise their network using beacons.
2. Tests that advertise their network using answers to probe requests. The tests that use probe responses are also divided into two parts:
2.1. Tests that use a sniffed probe response that was sent to the target from a legitimate source.
2.2. Tests that copy the target's probe requests, change a few parameters, and send it back.

**In all tests the frame check sequence is set to AAAA for easier reading in Wireshark.**