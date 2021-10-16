# Current Test
In this part we test a probe response attack by changing a sniffed probe response to the target device.
We use this to test length overflows.
Command to filter relevant results in Wireshark: 
`wlan.bssid == YOUR_MAC_ADDR or (wlan.sa == TARGET_MAC_ADDR and wlan.da == ff:ff:ff:ff:ff:ff)`

## Samsung galaxy s8+
* For ssid = B and sent ssid's length in [1, 2, 3, 4, 5], the shown ssid was in [B, BA, BAA, BAAA, BAAAA] and the authentication was successful. A probe request with the network name was sent to broadcast on every connection attempt.
* For ssid = B and send ssid's length = 6, the network was not shown in the networks' list of the s8+.

## Nexus 5
* For ssid = B and ssid's length = 1, the network was not shown in the nexus 5's networks list.

## LG G2
* Results similiar to the galaxy s8 plus' results.

## One plus
* Results similiar to the galaxy s8 plus' results.

## Samsung galaxy tab 3 lite
* Results similiar to the galaxy s8 plus' results.