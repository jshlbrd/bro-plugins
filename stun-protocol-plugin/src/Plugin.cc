#include "plugin/Plugin.h"
#include "STUN_UDP.h"
#include "STUN_UDP_MAGIC.h"

namespace plugin {
namespace Bro_STUN {

class Plugin : public plugin::Plugin {
public:
	plugin::Configuration Configure()
		{
		AddComponent(new ::analyzer::Component("STUN_UDP", ::analyzer::STUN_UDP::STUN_Analyzer::InstantiateAnalyzer));
		AddComponent(new ::analyzer::Component("STUN_UDP_MAGIC", ::analyzer::STUN_UDP_MAGIC::STUN_Analyzer::InstantiateAnalyzer));

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
