
#ifndef ANALYZER_PROTOCOL_STUN_STUN_RFC5389_H
#define ANALYZER_PROTOCOL_STUN_STUN_RFC5389_H
#include "events.bif.h"
#include "analyzer/protocol/udp/UDP.h"
#include "stun_RFC5389_pac.h"

namespace analyzer { namespace STUN_RFC5389 {

class STUN_Analyzer

: public analyzer::Analyzer {

public:
	STUN_Analyzer(Connection* conn);
	virtual ~STUN_Analyzer();

	// Overriden from Analyzer.
	virtual void Done();
	
	virtual void DeliverPacket(int len, const u_char* data, bool orig,
					uint64 seq, const IP_Hdr* ip, int caplen);
	

	static analyzer::Analyzer* InstantiateAnalyzer(Connection* conn)
		{ return new STUN_Analyzer(conn); }

protected:
	binpac::STUN_RFC5389::STUN_Conn* interp;
	
};

} } // namespace analyzer::* 

#endif
