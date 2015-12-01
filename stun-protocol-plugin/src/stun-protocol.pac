type STUN_UDP_MAGIC_PDU(is_orig: bool) = record {
	message_type:		uint16;
	message_len:		uint16;
	magic_cookie:		RE/\x21\x12\xa4\x42/;
	trans_id:		bytestring &length=12;
	#attributes:		STUN_ATTRIBUTE[] &until($input.length() == 0);
} &byteorder=bigendian &length=message_len+20;

type STUN_UDP_PDU(is_orig: bool) = record {
	message_type:		uint16;
	message_len:		uint16;
	message_trans_id:	bytestring &length=16;
	attributes: STUN_ATTRIBUTE[] &until($input.length() == 0);
} &byteorder=bigendian &length=message_len+20; 

type STUN_ATTRIBUTE = record {
	type:		uint16;
	length:		uint16;
	switch: 	case type of {
		0x0001	->	mapped_addr:	STUN_ADDRESS;
		0x0004	->	source_addr:	STUN_ADDRESS;
		0x0005	->	changed_addr:	STUN_ADDRESS;
		0x8020	->	xor_addr:	STUN_ADDRESS;
		0x8022	->	server:		STUN_SERVER(length);
	};
};

type STUN_ADDRESS = record {
	proto_family:	uint16;
	port:		uint16;
	ip:		uint32;
};

type STUN_SERVER(length: uint16) = record {
	version:	bytestring &length=length-1;
};
