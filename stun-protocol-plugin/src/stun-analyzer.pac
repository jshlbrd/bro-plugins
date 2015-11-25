refine flow STUN_Flow += {
	function proc_stun_rfc5389_header(hdr: STUN_RFC5389_PDU): bool
		%{
		BifEvent::generate_stun_rfc5389_header(connection()->bro_analyzer(), connection()->bro_analyzer()->Conn(), 
		${hdr.message_type},
		${hdr.message_len});

		return true;
		%}


	function proc_stun_rfc3489_header(hdr: STUN_RFC3489_PDU): bool
		%{
		BifEvent::generate_stun_rfc3489_header(connection()->bro_analyzer(), connection()->bro_analyzer()->Conn(), 
		${hdr.message_type}, 
		${hdr.message_len}); 

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



refine typeattr STUN_RFC3489_PDU += &let {
	proc: bool = $context.flow.proc_stun_rfc3489_header(this);
};

refine typeattr STUN_RFC5389_PDU += &let {
	proc: bool = $context.flow.proc_stun_rfc5389_header(this);
};

refine typeattr STUN_ADDRESS += &let {
	proc: bool = $context.flow.proc_stun_address(this);
};

refine typeattr STUN_SERVER += &let {
	proc: bool = $context.flow.proc_stun_server(this);
};
