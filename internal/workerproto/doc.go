// Package workerproto implements the private, versioned wire protocol between
// a gantry supervisor and its re-executed workers.
//
// Control messages are length-prefixed JSON. Ethernet data uses the same
// bounded length-prefix shape with raw payloads. A launch nonce links the
// independently inherited control and data channels, preventing a cross-wired
// worker from accepting authority from a different launch.
//
// Every declared length is validated before allocation. Unknown operations,
// non-monotonic request IDs, invalid framing, and unexpected response IDs end
// the connection: this is a private same-binary protocol, not a compatibility
// boundary where ambiguous input should be tolerated.
package workerproto
