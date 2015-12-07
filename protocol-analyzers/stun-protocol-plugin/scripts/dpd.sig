signature dpd_stun {
	ip-proto == udp
	payload /^.{4}\x21\x12\xa4\x42/
	enable "stun_UDP_MAGIC"
}
