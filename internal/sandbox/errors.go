package sandbox

import "errors"

// ExitNetworkNotIsolated is the process exit code used when greywall refuses to
// run because network access cannot be contained. It is distinct from a failure
// of the sandboxed command itself, so callers and CI can tell the two apart.
const ExitNetworkNotIsolated = 78

// ErrNetworkNotIsolated is returned when the sandbox cannot be given its own
// network namespace.
//
// Without one, the sandboxed process shares the host's network stack: it can
// reach the internet directly, host-local services on 127.0.0.1, and cloud
// instance metadata endpoints. Proxy environment variables are then the only
// remaining control, and any program is free to ignore them.
//
// greywall is deny-by-default, so it refuses to run rather than offer the
// appearance of containment. (greywatch is allow-by-default observability and
// is exempt.)
var ErrNetworkNotIsolated = errors.New("network access cannot be contained: the sandbox is unable to create a network namespace")
