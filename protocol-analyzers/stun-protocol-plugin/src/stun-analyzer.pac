refine flow STUN_Flow += {
	function proc_stun_udp_magic_header(udp_magic: STUN_UDP_MAGIC_PDU): bool
		%{
		BifEvent::generate_stun_udp_magic_header(connection()->bro_analyzer(), connection()->bro_analyzer()->Conn(), 
		${udp_magic.message_type},
		${udp_magic.message_len});

		return true;
		%}


	function proc_stun_udp_header(udp_hdr: STUN_UDP_PDU): bool
		%{
		BifEvent::generate_stun_udp_header(connection()->bro_analyzer(), connection()->bro_analyzer()->Conn(), 
		${udp_hdr.message_type}, 
		${udp_hdr.message_len}); 

		return true;
		%}
	
	function proc_stun_address(address: STUN_ADDRESS): bool
		%{
		BifEvent::generate_stun_address(connection()->bro_analyzer(), connection()->bro_analyzer()->Conn(), 
		${address.proto_family},
		${address.port},
		new AddrVal(htonl(${address.ip})));
	
		return true;
		%}

	function proc_stun_server(server: STUN_SERVER): bool
		%{
		BifEvent::generate_stun_server(connection()->bro_analyzer(), connection()->bro_analyzer()->Conn(), 
		bytestring_to_val(${server.version}));

		return true;
		%}
};



refine typeattr STUN_UDP_PDU += &let {
	proc: bool = $context.flow.proc_stun_udp_header(this);
};

refine typeattr STUN_UDP_MAGIC_PDU += &let {
	proc: bool = $context.flow.proc_stun_udp_magic_header(this);
};

refine typeattr STUN_ADDRESS += &let {
	proc: bool = $context.flow.proc_stun_address(this);
};

refine typeattr STUN_SERVER += &let {
	proc: bool = $context.flow.proc_stun_server(this);
};
