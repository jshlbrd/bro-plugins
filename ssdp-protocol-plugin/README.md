
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
#open	2015-12-05-09-27-41
#fields	ts	uid	id.orig_h	id.orig_p	id.resp_h	id.resp_p	ssdp_type	search_target	server	usn	location	headers
#types	time	string	addr	port	addr	port	string	string	string	string	string	set[string]
1129437657.087179	C1KObE2AN9Uila8uI6	192.168.0.1	1900	239.255.255.250	1900	RESPONSE	upnp:rootdevice	Microsoft-Windows-NT/5.1 UPnP/1.0 UPnP-Device-Host/1.0	uuid:d241a30b-a851-4c50-8ed1-b75f3f9014dc::upnp:rootdevice	http://192.168.0.1:2869/upnphost/udhisapi.dll?content=uuid:d241a30b-a851-4c50-8ed1-b75f3f9014dc	USN,Location,Cache-Control,NTS,Host,NT,Server
#close	2015-12-05-09-27-41
```

### TODO
* Support multiple SSDP messages over a single connection
* Clean up code in src/ssdp-protocol.pac and src/ssdp-analyzer.pac
* More documentation
* Improve DPD sig for SSDP RESPONSE
