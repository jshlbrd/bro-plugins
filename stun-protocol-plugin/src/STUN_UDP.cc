#include "STUN_UDP.h"
#include "Reporter.h"
#include "events.bif.h"

using namespace analyzer::STUN_UDP;

STUN_Analyzer::STUN_Analyzer(Connection* c)

: analyzer::Analyzer("STUN_UDP", c)

	{
	interp = new binpac::STUN_UDP::STUN_Conn(this);
	
	}

STUN_Analyzer::~STUN_Analyzer()
	{
	delete interp;
	}

void STUN_Analyzer::Done()
	{
	
	Analyzer::Done();
	
	}

void STUN_Analyzer::DeliverPacket(int len, const u_char* data,
	 			  bool orig, uint64 seq, const IP_Hdr* ip, int caplen)
	{
	Analyzer::DeliverPacket(len, data, orig, seq, ip, caplen);

	try
		{
		interp->NewData(orig, data, data + len);
		}
	catch ( const binpac::Exception& e )
		{
		ProtocolViolation(fmt("Binpac exception: %s", e.c_msg()));
		}
	}
