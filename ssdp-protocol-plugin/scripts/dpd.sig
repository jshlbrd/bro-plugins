signature dpd_ssdp {
	ip-proto == udp
	payload /^(NOTIFY|M-SEARCH|HTTP\/1\.1 200 OK)/
	enable "ssdp"
}
