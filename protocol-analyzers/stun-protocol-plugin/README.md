
Bro::STUN
=================================

This plugin is a basic STUN analyzer for Bro. It currently supports UDP. 

This plugin is in-development and will not produce the intended STUN protocol metadata in its current state. 

### Installation

See the plugin documentation here: https://www.bro.org/sphinx-git/devel/plugins.html

### TODO
* Figure out best method of grabbing individual STUN packets and logging them from UDP streams
* Prototype scripts/main.bro
* Fill out scripts/const.bro
* Clean up src/stun-protocol.pac and src/stun-analyzer.pac
