module STUN;

export {
	redef enum Log::ID += { LOG };

	type Info: record {
		## Timestamp for when the event happened.
		ts:     time    &log;
		## Unique ID for the connection.
		uid:    string  &log;
		## The connection's 4-tuple of endpoint addresses/ports.
		id:     conn_id &log;
	};

	## Event that can be handled to access the STUN record.
	global log_stun: event(rec: Info);
}

redef record connection += {
	stun: Info &optional;
};

const ports = { 3478/udp };
redef likely_server_ports += { ports };

event bro_init() &priority=5
	{
	Log::create_stream(STUN::LOG, [$columns=Info, $ev=log_stun, $path="stun"]);
	Analyzer::register_for_ports(Analyzer::ANALYZER_STUN_UDP, ports);
	Analyzer::register_for_ports(Analyzer::ANALYZER_STUN_UDP_MAGIC, ports);
	}

function set_session(c: connection)
	{
	if ( ! c?$stun )
		{
		c$stun = [$ts=network_time(),$id=c$id,$uid=c$uid];
		}
	}

event stun_rfc3489_header(c: connection, message_type: count, message_length: count)
	{
	set_session(c);
	Log::write(STUN::LOG, c$stun);
	}


event stun_rfc5389_header(c: connection, message_type: count, message_length: count)
	{
	set_session(c);
	Log::write(STUN::LOG, c$stun);
	}
