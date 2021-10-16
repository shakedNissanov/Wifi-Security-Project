# Current Test
In this part we use a beacon attack to test ssid overflows.
Command to filter relevant results in Wireshark: `wlan.bssid == YOUR_MAC_ADDR`

## Samsung galaxy s8+
* For all ssid values tested in [BB, BBB, B*100, B*1000] for length = 1 the authentication was successful.
The value shown on the s8+ screen was B, but wireshark showed that the message included all of the extra B's.
* For ssid = B * 2000, my virtual machine crashed and we were unable to complete this test.
* For ssid = B * 4000, scapy notified us that the message is too long and exited without sending anything.

## Nexus 5
* For all ssid values tested in [B*100, B*500, B*1000] for length = 1 the authentication was successful. The value shown on the s8+ screen was B, but wireshark showed that the message included all of the extra B's.

## LG G2
* Results similar to the galaxy s8+.

## One plus
* Results similar to the galaxy s8+.

## Samsung galaxy tab 3 lite
* Results similar to the galaxy s8+.