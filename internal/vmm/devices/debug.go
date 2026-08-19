package devices

import "os"

// DebugIO enables per-access tracing of port I/O and interrupt delivery. The
// device models and both x86 backends read it, so it is resolved once here
// rather than per call site.
var DebugIO = os.Getenv("GANTRY_DEBUG") != ""
