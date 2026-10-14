package httpx

import (
	"fmt"
	"runtime"
)

// anonymousClientVersion is the OpenCode release the keyless free tier expects
// to see in the User-Agent. Upstream accepts a range of releases, so this only
// needs bumping when it starts rejecting older ones.
const anonymousClientVersion = "2.0.29"

// UserAgent reports the gateway as an OpenCode build for the keyed lanes. The
// legacy "opencode/<version> (<os> <arch>; <runtime>)" shape is kept there for
// compatibility with older Zen deployments.
func UserAgent() string {
	return fmt.Sprintf("opencode/1.18.31 (%s %s; %s)", runtime.GOOS, runtime.GOARCH, runtime.Version())
}

// AnonymousUserAgent reports the client shape the keyless free tier checks:
// "opencode/<channel>/<version>/<name>". Anything else is rejected with 403
// FreeTierError even when the rest of the request is identical.
func AnonymousUserAgent() string {
	return "opencode/latest/" + anonymousClientVersion + "/cli"
}
