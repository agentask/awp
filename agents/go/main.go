// Command go-agent implements trip-planner.local, one of three AWP agents
// (Go, Python, Rust) forming a triangle demo: each node initiates exactly
// one outbound thread and receives on the other edge, so all three pairs
// talk directly (true all-to-all for n=3).
//
// trip-planner.local (this binary) initiates a thread with concierge.local
// and separately receives-and-replies on a thread activities.local opens
// with it. Both are ordinary AWP threads — this binary doesn't need to
// know it's "in a triangle."
package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/agentask/awp/internal/envelope"
)

func main() {
	cfg, err := loadConfig()
	if err != nil {
		log.Fatalf("config: %v", err)
	}

	node, err := NewNode(cfg.Domain, "k1")
	if err != nil {
		log.Fatalf("new node: %v", err)
	}

	llm := NewGrokClient(cfg.XAIAPIKey, cfg.Model)
	tracker := newConversationTracker()
	node.OnMessage = makeMessageHandler(llm, cfg.Domain, tracker)
	openerThread := envelope.NewID()

	bindAddr := fmt.Sprintf("0.0.0.0:%d", cfg.Port)
	srv := &http.Server{Addr: bindAddr, Handler: node}
	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("serve: %v", err)
		}
	}()

	// Give the listener a moment to actually be up before finalizing (the
	// index's inbox URL points at it) and before sending the opener.
	time.Sleep(100 * time.Millisecond)

	// The bind address (0.0.0.0) is not something a peer can connect to —
	// the index advertises AdvertiseHost instead (127.0.0.1 natively, this
	// agent's own compose service name under docker compose).
	inboxURL := fmt.Sprintf("http://%s:%d/awp/inbox", cfg.AdvertiseHost, cfg.Port)
	if err := node.Finalize(inboxURL, cfg.indexURLFor); err != nil {
		log.Fatalf("finalize index: %v", err)
	}

	fmt.Printf("%s listening on http://%s, advertising %s (peers: %v)\n", cfg.Domain, bindAddr, inboxURL, cfg.Peers)

	go sendOpener(node, cfg, tracker, openerThread)

	// Block forever serving the inbox; Ctrl-C exits.
	select {}
}

// sendOpener sends the opening message to concierge.local shortly after
// startup, matching the existing Python demo's _send_opener pattern (1s
// delay to let both sides finish starting up). The opener text is seeded
// into tracker's history as our own ("assistant") turn so that when
// concierge.local's reply lands on this same thread, the Grok call
// carrying the exchange forward sees the full conversation, not just the
// inbound half of it.
func sendOpener(node *Node, cfg *config, tracker *conversationTracker, thread string) {
	time.Sleep(1 * time.Second)

	const peerDomain = "concierge.local"
	if _, ok := cfg.Peers[peerDomain]; !ok {
		fmt.Fprintf(os.Stderr, "%s: no AWP_PEERS entry for %s, skipping opener\n", cfg.Domain, peerDomain)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	fmt.Printf("[%s] -> [%s] (opener): %s\n", cfg.Domain, peerDomain, openerText)
	if _, err := node.Send(ctx, "message", peerDomain, thread, nil, textBodyJSON(openerText)); err != nil {
		fmt.Fprintf(os.Stderr, "%s: send opener to %s failed: %v\n", cfg.Domain, peerDomain, err)
		return
	}
	tracker.append(thread, ChatMessage{Role: "assistant", Content: openerText})
}
