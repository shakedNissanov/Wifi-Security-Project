# Current Test
In this part we use a beacon attack to test length overflows.
Command to filter relevant results in Wireshark: `wlan.bssid == YOUR_MAC_ADDR`

## Samsung galaxy s8+
* For ssid = B and sent ssid's length in [1, 2, 3, 4, 5], the shown ssid was in [B, BA, BAA, BAAA, BAAAA] and the authentication was successful.
* For ssid = B and send ssid's length = 6, the network was not shown in the networks' list of the s8+.

## Nexus 5
* For ssid = B and sent ssid's length in [1, 2, 3, 4, 5], the shown ssid was in [B, BA, BAA, BAAA, BAAAA]
and the authentication was successful.
* For ssid = B and sent ssid's length in range(6, 22), the shown ssid was BAAAA and next to it were random chars that were not sent in the packet. This are probably chars from the device itself. If we try to connect to this network, it says the network is saved but it does not say connecting like what happend in the first bullet. we theorize this is because there are non printable chars in the network name that we get from the device.

## LG G2
* Like the samsusng galaxy s8+, the G2 shows the network and connects to it for all ssid = B and send ssid's length in [1, 2, 3, 4, 5].
* For ssid's length = 6 the network is not shown on the G2's networks list.

## One Plus
* For ssid = B and sent ssid's length in [1, 2, 3, 4, 5], the shown ssid was in [B, BA, BAA, BAAA, BAAAA] and the authentication was successful.
* For ssid = B and ssid's length = 6, the shown ssid was BAAAA with a non printable char next to it. The difference between this test and the nexus 5 is that here if this is the first time connecting to the network after restarting the device's Wifi, the device will send the non printable char on a probe request, which means we can see it.

## Samsung galaxy tab 3 lite
* Results similar to the galaxy s8+.