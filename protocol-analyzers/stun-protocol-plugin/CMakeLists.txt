project(Bro-Plugin-STUN)

cmake_minimum_required(VERSION 2.8)

if ( NOT BRO_DIST )
    message(FATAL_ERROR "BRO_DIST not set")
endif ()

set(CMAKE_MODULE_PATH ${BRO_DIST}/cmake)

include(BroPlugin)

bro_plugin_begin(Bro STUN)
bro_plugin_cc(src/Plugin.cc)
bro_plugin_cc(src/STUN_UDP.cc)
bro_plugin_cc(src/STUN_UDP_MAGIC.cc)
bro_plugin_bif(src/events.bif)
bro_plugin_pac(src/stun_UDP.pac src/stun-analyzer.pac src/stun-protocol.pac)
bro_plugin_pac(src/stun_UDP_MAGIC.pac src/stun-analyzer.pac src/stun-protocol.pac)
bro_plugin_end()
