
Bro::SSDP
=================================

This plugin is an SSDP protocol analyzer for Bro. The analyzer parses the discovery phase of the SSDP protocol. When used for processing SSDP network traffic, this plugin will generate ssdp.log-- this log contains the type of SSDP discovery message (REQUEST or RESPONSE), all headers seen in the message, and metadata relevant to the message (location of the description file, USN, server information, etc). 

It should be noted that SSDP network traffic may represent a significant portion of overall network traffic, so caution is advised if deploying this analyzer in a production environment-- it is possible that this analyzer will generate large ssdp.log files. I suggest profiling overall network traffic by searching conn.log for any UDP connections on port 1900 to get a sense of how much potential traffic will be parsed with this analyzer plugin. Whitelisting of specific values will reduce the log output of the analyzer.

Additionally, this plugin will only work as intended with Bro 2.4-214 or later. Bro 2.4-214 can be pulled at https://github.com/bro/bro. 

As with any open-source tool, I value feedback and suggestions on how to improve this plugin.

### Installation

See the plugin documentation here: https://www.bro.org/sphinx-git/devel/plugins.html

### Log output
```
#separator \x09
#set_separator	,
#empty_field	(empty)
#unset_field	-
#path	ssdp
#open	2015-12-05-07-58-30
#fields	ts	uid	id.orig_h	id.orig_p	id.resp_h	id.resp_p	ssdp_type	search_target	server	usn	location	headers
#types	time	string	addr	port	addr	port	string	string	string	string	string	set[string]
1129437657.087179	CD7i13XosewnTRf01	192.168.0.1	1900	239.255.255.250	1900	RESPONSE	upnp:rootdevice	Microsoft-Windows-NT/5.1 UPnP/1.0 UPnP-Device-Host/1.0	uuid:d241a30b-a851-4c50-8ed1-b75f3f9014dc::upnp:rootdevice	http://192.168.0.1:2869/upnphost/udhisapi.dll?content=uuid:d241a30b-a851-4c50-8ed1-b75f3f9014dc	USN,Cache-Control,Server,Location,NT,Host,NTS
1193675992.484388	CSMe0u18R6hAeUEOy7	169.254.144.40	1043	239.255.255.250	1900	REQUEST	urn:schemas-upnp-org:device:InternetGatewayDevice:1	-	-	-	MX,ST,Host,Man
1193675992.536420	CyNQw11nk6NFgrLkug	169.254.144.40	1047	239.255.255.250	1900	REQUEST	urn:schemas-upnp-org:device:InternetGatewayDevice:1	-	-	-	MX,ST,Host,Man
1193676053.973216	CkW8jG3iSTYRMVCyK2	169.254.144.40	1056	239.255.255.250	1900	REQUEST	urn:schemas-upnp-org:device:InternetGatewayDevice:1	-	-	-	MX,ST,Host,Man
1193676053.973382	CnmCKs1cJ2QguJNJ56	172.202.246.57	1057	239.255.255.250	1900	REQUEST	urn:schemas-upnp-org:device:InternetGatewayDevice:1	-	-	-	MX,ST,Host,Man
1233324942.180664	CuHRjB2WcdR8901cD3	172.31.2.87	35403	239.255.255.250	1900	RESPONSE	urn:schemas-upnp-org:service:storage:1	Linux/2.6.10-iop1-9, UPnP/1.0, Intel SDK for UPnP devices /1.2	uuid:Upnp-TVEmulator-000E0CF63BEE::urn:schemas-upnp-org:service:storage:1	http://172.31.2.87:49152/tvdevicedesc.xml	LOCATION,USN,HOST,CACHE-CONTROL,NT,SERVER,NTS
1269641566.811327	CZggEq35P27Cdfbdjf	192.168.1.1	1900	239.255.255.250	1900	RESPONSE	upnp:rootdevice	F5D8633-4-v1000/1.0 UPnP/1.0	uuid:00000000-0000-0001-0000-001cdf829145::upnp:rootdevice	http://192.168.1.1:80/igd.xml	USN,Cache-Control,Location,NT,SERVER,Host,NTS
1269641566.991451	C5fpJ34SKooUqmTmw4	fe80::a021:131:366d:483a	60734	ff02::c	1900	REQUEST	urn:Microsoft Windows Peer Name Resolution Protocol: V4:IPV6:LinkLocal	-	-	-	MX,ST,Host,Man
#close	2015-12-05-07-58-30
```

### TODO
* Clean up code in src/ssdp-protocol.pac and src/ssdp-analyzer.pac
* More documentation
* Improve DPD sig for SSDP RESPONSE
