type STUN_USERNAME_PAD = RE/\x20?*/;
type STUN_SOFTWARE_PAD = RE/\x00?*/;

type STUN_UDP_MAGIC_PDU(is_orig: bool) = record {
	message_type:		uint16;
	message_len:		uint16;
	magic_cookie:		RE/\x21\x12\xa4\x42/;
	message_trans_id:	bytestring &length=12;
	attributes:		STUN_ATTRIBUTE(is_orig,message_type,message_trans_id)[] &until($input.length() == 0);
} &byteorder=bigendian &length=message_len+20;

type STUN_UDP_PDU(is_orig: bool) = record {
	message_type:		uint16;
	message_len:		uint16;
	message_trans_id:	bytestring &length=16;
	attributes: STUN_ATTRIBUTE(is_orig,message_type,message_trans_id)[] &until($input.length() == 0);
} &byteorder=bigendian &length=message_len+20; 

type STUN_ATTRIBUTE(is_orig: bool, message_type: uint16, message_trans_id: bytestring) = record {
	attr_type:	uint16;
	attr_len:	uint16;
	switch: 	case attr_type of {
		0x0001	->	mapped_addr:		STUN_ADDRESS(is_orig,message_type,message_trans_id,attr_type);
		0x0002	->	resp_addr:		STUN_ADDRESS(is_orig,message_type,message_trans_id,attr_type);
		0x0003	->	change_req:		STUN_ADDRESS(is_orig,message_type,message_trans_id,attr_type);
		0x0004	->	source_addr:		STUN_ADDRESS(is_orig,message_type,message_trans_id,attr_type);
		0x0005	->	changed_addr:		STUN_ADDRESS(is_orig,message_type,message_trans_id,attr_type);
		0x0006	->	username:		STUN_USERNAME(is_orig,message_type,message_trans_id,attr_len);
		0x0007	->	password:		STUN_PASSWORD(is_orig,message_type,message_trans_id,attr_len);
		0x0008	->	message_integrity:	STUN_MSG_INTEGRITY(is_orig,message_type,message_trans_id,attr_len);
		0x0009	->	error_code:		STUN_ERROR_CODE(is_orig,message_type,message_trans_id,attr_len);
		0x000b	->	reflected_from:		STUN_ADDRESS(is_orig,message_type,message_trans_id,attr_type);
		0x8022	->	software:		STUN_SOFTWARE(is_orig,message_type,message_trans_id,attr_len);
		0x8028	->	fingerprint:		STUN_FINGERPRINT(is_orig,message_type,message_trans_id,attr_len);
		default	->	unknown:		bytestring &length=attr_len;
	};
};

type STUN_ADDRESS(is_orig: bool, message_type: uint16, message_trans_id: bytestring, attr_type: uint16) = record {
	proto_family:	uint16;
	port:		uint16;
	ip:		uint32;
};

type STUN_USERNAME(is_orig: bool, message_type: uint16, message_trans_id: bytestring, attr_len: uint16) = record {
	username:	bytestring &length=attr_len;
	pad:		STUN_USERNAME_PAD;
};

type STUN_PASSWORD(is_orig: bool, message_type: uint16, message_trans_id: bytestring, attr_len: uint16) = record {
	password:	bytestring &length=attr_len;
};

type STUN_SOFTWARE(is_orig: bool, message_type: uint16, message_trans_id: bytestring, attr_len: uint16) = record {
	version:	bytestring &length=attr_len;
	pad:		STUN_SOFTWARE_PAD;
};

type STUN_MSG_INTEGRITY(is_orig: bool, message_type: uint16, message_trans_id: bytestring, attr_len: uint16) = record {
	hmac_sha1:	bytestring &length=attr_len;
};

type STUN_ERROR_CODE(is_orig: bool, message_type: uint16, message_trans_id: bytestring, attr_len: uint16) = record {
	reserved:		uint16;
	error_class:		uint8;
	error_code:		uint8;
	error_reason_phrase:	bytestring &length=attr_len-4;
} &length=attr_len;

type STUN_FINGERPRINT(is_orig: bool, message_type: uint16, message_trans_id: bytestring, attr_len: uint16) = record {
	crc_32:	bytestring &length=attr_len;
};
