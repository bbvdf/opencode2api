package gateway

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

// freeAbuseCooldown is the base penalty window for an exit the free tier has
// refused. Upstream says retrying lengthens the penalty, so the only useful
// reaction is to stop sending requests from that exit until the window expires.
const freeAbuseCooldown = 30 * time.Minute

// maxFreeAbuseCooldown caps the exponential backoff applied when the same exit
// is blocked again straight after a window expired.
const maxFreeAbuseCooldown = 6 * time.Hour

// freeAbusePeekLimit bounds how much of a rejected body is inspected.
const freeAbusePeekLimit = 8 << 10

// freeTierBlockedMessage is what clients get instead of the upstream text,
// which tells operators on a proxy to turn their VPN off and describes neither
// this gateway nor the real cause.
const freeTierBlockedMessage = "the free tier upstream is blocking this exit IP after detecting abuse; free models are paused until the penalty expires. Paid tiers are unaffected."

// errFreeTierBlocked marks a request that stopped because every anonymous exit
// was inside its abuse penalty window. Handlers map it to 503
// free_tier_ip_blocked.
var errFreeTierBlocked = errors.New("free tier is blocking this exit IP after upstream abuse detection")

// isFreeAbuseBlock reports whether body carries OpenCode's IP-abuse rejection
// for the keyless free tier. It deliberately ignores the FreeTierError wording
// ("can only be used from within OpenCode"): that one describes a request-shape
// rejection that a different body can fix, while this one follows the exit and
// only expires with time.
func isFreeAbuseBlock(body []byte) bool {
	if len(body) == 0 {
		return false
	}
	text := strings.ToLower(string(body))
	return strings.Contains(text, "abusive traffic") ||
		strings.Contains(text, "available from your current network")
}

// exitBlocks records the current free-tier penalty deadline per proxy exit, so
// the anonymous lane, the keyed fallback that leaves from the same exit and the
// background availability probes all stop feeding the penalty. A nil value is
// valid and never blocks anything.
type exitBlocks struct {
	mu      sync.Mutex
	until   map[string]time.Time
	strikes map[string]int
}

func newExitBlocks() *exitBlocks {
	return &exitBlocks{until: map[string]time.Time{}, strikes: map[string]int{}}
}

// Blocked reports whether exit is still inside its penalty window.
func (b *exitBlocks) Blocked(exit string) bool {
	if b == nil {
		return false
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	deadline, ok := b.until[exit]
	if !ok {
		return false
	}
	if time.Now().Before(deadline) {
		return true
	}
	delete(b.until, exit)
	return false
}

// Block starts the penalty window of exit, or extends it when the exit is
// already cooling down. Repeated blocks escalate exponentially so a probe or a
// client retry cannot keep the exit inside a fresh penalty every hour. It
// returns the new strike count and the window it applied.
func (b *exitBlocks) Block(exit string) (int, time.Duration) {
	if b == nil {
		return 0, 0
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.strikes[exit]++
	strikes := b.strikes[exit]
	cooldown := freeAbuseCooldown
	for i := 1; i < strikes && cooldown < maxFreeAbuseCooldown; i++ {
		cooldown *= 2
	}
	if cooldown > maxFreeAbuseCooldown {
		cooldown = maxFreeAbuseCooldown
	}
	b.until[exit] = time.Now().Add(cooldown)
	return strikes, cooldown
}

// Clear forgets the penalty and the strike count of exit, which is what a
// successful anonymous request means.
func (b *exitBlocks) Clear(exit string) {
	if b == nil {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	delete(b.until, exit)
	delete(b.strikes, exit)
}

// peekedBody replaces resp.Body with a reader that replays the buffered prefix
// before the rest of the original body, so a response inspected for the abuse
// wording can still be forwarded to the client verbatim.
type peekedBody struct {
	io.Reader
	io.Closer
}

// peekResponseBody buffers up to limit bytes of resp.Body and puts them back.
// It returns nil when the response has no body.
func peekResponseBody(resp *http.Response, limit int64) []byte {
	if resp == nil || resp.Body == nil {
		return nil
	}
	buffered, _ := io.ReadAll(io.LimitReader(resp.Body, limit))
	if len(buffered) == 0 {
		return nil
	}
	resp.Body = peekedBody{Reader: io.MultiReader(bytes.NewReader(buffered), resp.Body), Closer: resp.Body}
	return buffered
}
