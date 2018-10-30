# reflector

reflector2.c is a c program that sniffs packets destined for its IP address, and responds by mirroring the functionality of the source.

It does this by reconstructing the packet with the original source as the new destination, and sends an identical payload to the source. The original source then provides the response to the reflector, which is then mirrored back to the source. This way the reflector looks like it is running identical services as whatever source machine a packet comes from.
