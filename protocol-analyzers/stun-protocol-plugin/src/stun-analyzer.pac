refine flow STUN_Flow += {
	function proc_stun_udp_magic_header(udp_magic: STUN_UDP_MAGIC_PDU): bool
		%{
                connection()->bro_analyzer()->ProtocolConfirmation();

		BifEvent::generate_stun_udp_magic_header(connection()->bro_analyzer(), connection()->bro_analyzer()->Conn(), 
		${udp_magic.message_type});

		return true;
		%}

	function proc_stun_udp_header(udp_hdr: STUN_UDP_PDU): bool
		%{
                connection()->bro_analyzer()->ProtocolConfirmation();

		BifEvent::generate_stun_udp_header(connection()->bro_analyzer(), connection()->bro_analyzer()->Conn(), 
		${udp_hdr.message_type}); 

		return true;
		%}

	function proc_stun_attribute(attr: STUN_ATTRIBUTE): bool
		%{
                connection()->bro_analyzer()->ProtocolConfirmation();

		BifEvent::generate_stun_attribute(connection()->bro_analyzer(), connection()->bro_analyzer()->Conn(),
		${attr.is_orig}, 
		${attr.message_type},
		${attr.attr_type});


		return true;
		%}

	function proc_stun_address(address: STUN_ADDRESS): bool
		%{
		BifEvent::generate_stun_address(connection()->bro_analyzer(), connection()->bro_analyzer()->Conn(),
		${address.is_orig},
		${address.message_type}, 
		bytestring_to_val(${address.message_trans_id}),
		${address.attr_type},
		${address.proto_family},
		new AddrVal(htonl(${address.ip})),
		// Defaulting to UDP, but this might not always be true?
		new PortVal(${address.port},TRANSPORT_UDP));
	
		return true;
		%}

	function proc_stun_username(user: STUN_USERNAME): bool
		%{
		BifEvent::generate_stun_username(connection()->bro_analyzer(), connection()->bro_analyzer()->Conn(), 
 		${user.is_orig},
                ${user.message_type}, 
		bytestring_to_val(${user.username}));

		return true;
		%}

	function proc_stun_password(pass: STUN_PASSWORD): bool
		%{
		BifEvent::generate_stun_password(connection()->bro_analyzer(), connection()->bro_analyzer()->Conn(), 
		${pass.is_orig},
                ${pass.message_type}, 
		bytestring_to_val(${pass.password}));
		
		return true;
		%}


	function proc_stun_error_code(error: STUN_ERROR_CODE): bool
		%{
		BifEvent::generate_stun_error_code(connection()->bro_analyzer(), connection()->bro_analyzer()->Conn(), 
		${error.is_orig},
                ${error.message_type}, 
		${error.error_class},
		${error.error_code},
		bytestring_to_val(${error.error_reason_phrase}));

		return true;
		%}

        function proc_stun_software(software: STUN_SOFTWARE): bool
                %{
                BifEvent::generate_stun_software(connection()->bro_analyzer(), connection()->bro_analyzer()->Conn(),
		${software.is_orig},
                ${software.message_type}, 
                bytestring_to_val(${software.version}));

                return true;
                %}


};

refine typeattr STUN_UDP_PDU += &let {
	proc: bool = $context.flow.proc_stun_udp_header(this);
};

refine typeattr STUN_UDP_MAGIC_PDU += &let {
	proc: bool = $context.flow.proc_stun_udp_magic_header(this);
};

refine typeattr STUN_ATTRIBUTE += &let {
	proc: bool = $context.flow.proc_stun_attribute(this);
};

refine typeattr STUN_ADDRESS += &let {
	proc: bool = $context.flow.proc_stun_address(this);
};

refine typeattr STUN_USERNAME += &let {
        proc: bool = $context.flow.proc_stun_username(this);
};

refine typeattr STUN_PASSWORD += &let {
        proc: bool = $context.flow.proc_stun_password(this);
};

refine typeattr STUN_ERROR_CODE += &let {
        proc: bool = $context.flow.proc_stun_error_code(this);
};

refine typeattr STUN_SOFTWARE += &let {
	proc: bool = $context.flow.proc_stun_software(this);
};
