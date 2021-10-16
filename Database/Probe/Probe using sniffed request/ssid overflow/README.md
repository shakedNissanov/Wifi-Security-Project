# Current Test
In this part we use a probe attack using a sniffed request to test ssid overflows.
Command to filter relevant results in Wireshark: 
`wlan.bssid == YOUR_MAC_ADDR or (wlan.sa == TARGET_MAC_ADDR and wlan.da == ff:ff:ff:ff:ff:ff)`

## Samsung galaxy s8+
* For all ssid values tested in [B*5, B*100, B*500] for length = 1 the authentication was successful. The value shown on the s8+ screen was B, but wireshark showed that the message included all of the extra B's.

## Nexus 5
* For all ssid values tested in [B, BB, BBBBBBBBBBBBBBBBBBB] for length = 1 the network was not shown in the nexus 5's networks list.

## LG G2
* Results similar to the test's results on the samsung galaxy s8+.

## One plus
* Results similar to the test's results on the nexus 5.

## Samsung galaxy tab 3 lite
* Results similar to the test's results on the samsung galaxy s8+.