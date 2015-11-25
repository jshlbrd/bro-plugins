#include "plugin/Plugin.h"
#include "STUN_RFC3489.h"
#include "STUN_RFC5389.h"

namespace plugin {
namespace Bro_STUN {

class Plugin : public plugin::Plugin {
public:
	plugin::Configuration Configure()
		{
		AddComponent(new ::analyzer::Component("STUN_RFC3489", ::analyzer::STUN_RFC3489::STUN_Analyzer::InstantiateAnalyzer));
		AddComponent(new ::analyzer::Component("STUN_RFC5389", ::analyzer::STUN_RFC5389::STUN_Analyzer::InstantiateAnalyzer));

		plugin::Configuration config;
		config.name = "Bro::STUN";
		config.description = "STUN protocol analyzer";
		config.version.major = 0;
		config.version.minor = 1;
		return config;
		}
} plugin;

}
}
