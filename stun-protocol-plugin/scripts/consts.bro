module STUN;

export {

	const msg_type = {
		[0x0001] = "Binding Request",
		[0x0101] = "Binding Response"
	} &default = function(n: count): string { return fmt("msg_type-%d", n); };
}
