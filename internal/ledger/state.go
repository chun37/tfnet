package ledger

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
)

// State is the deterministic projection of the ledger.
type State struct {
	Members  map[string]Subject // node_id -> latest committed subject
	NextSeq  uint64
	PrevHash [32]byte
}

// NewState returns the empty initial state (before any entries).
func NewState() *State {
	return &State{Members: map[string]Subject{}}
}

// MemberIDs returns the current member IDs in sorted order.
func (s *State) MemberIDs() []string {
	ids := make([]string, 0, len(s.Members))
	for id := range s.Members {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

// MemberByOverlayIP returns the node_id of the member whose overlay_ip matches
// the argument, or "" if none. Used by propose-* to fail fast on IP collisions
// rather than waiting until commit-time replay would catch them.
func (s *State) MemberByOverlayIP(ip string) string {
	for id, m := range s.Members {
		if m.OverlayIP == ip {
			return id
		}
	}
	return ""
}

// RequiredApprovers returns the node_ids that MUST sign the given entry per
// the N-of-N rule (§3.2), evaluated against the receiver's current state.
//
// Note: M is interpreted as the post-state for ADD (members ∪ {new}) and
// the post-state for REMOVE (members \ {removed}). For GENESIS, it is the
// set of subjects being introduced.
func (s *State) RequiredApprovers(e *Entry) (map[string]struct{}, error) {
	switch e.Op {
	case OpGenesis:
		if s.NextSeq != 0 {
			return nil, errors.New("GENESIS only valid as seq=0")
		}
		req := map[string]struct{}{}
		seen := map[string]bool{}
		for _, sub := range e.Subjects {
			if seen[sub.NodeID] {
				return nil, fmt.Errorf("duplicate genesis subject: %s", sub.NodeID)
			}
			seen[sub.NodeID] = true
			req[sub.NodeID] = struct{}{}
		}
		return req, nil
	case OpAdd:
		if e.Subject == nil {
			return nil, errors.New("ADD requires subject")
		}
		req := map[string]struct{}{}
		for id := range s.Members {
			req[id] = struct{}{}
		}
		req[e.Subject.NodeID] = struct{}{}
		return req, nil
	case OpRemove:
		if e.Subject == nil {
			return nil, errors.New("REMOVE requires subject")
		}
		if _, ok := s.Members[e.Subject.NodeID]; !ok {
			return nil, fmt.Errorf("REMOVE: %s is not a member", e.Subject.NodeID)
		}
		req := map[string]struct{}{}
		for id := range s.Members {
			if id != e.Subject.NodeID {
				req[id] = struct{}{}
			}
		}
		return req, nil
	default:
		return nil, fmt.Errorf("unknown op: %q", e.Op)
	}
}

// MissingApprovers reports approvers required by the entry but absent from
// its current approvals map.
func (s *State) MissingApprovers(e *Entry) ([]string, error) {
	req, err := s.RequiredApprovers(e)
	if err != nil {
		return nil, err
	}
	var miss []string
	for id := range req {
		if _, ok := e.Approvals[id]; !ok {
			miss = append(miss, id)
		}
	}
	sort.Strings(miss)
	return miss, nil
}

// pubkeysForVerify returns the Ed25519 verification keys for every node_id
// that could legitimately appear in an entry's approvals, given the
// receiver's current state and the entry's content.
func (s *State) pubkeysForVerify(e *Entry) (map[string]ed25519.PublicKey, error) {
	pks := map[string]ed25519.PublicKey{}
	for id, m := range s.Members {
		pk, err := decodeEdPub(m.IdentityPubkey)
		if err != nil {
			return nil, fmt.Errorf("member %s identity_pubkey: %w", id, err)
		}
		pks[id] = pk
	}
	switch e.Op {
	case OpGenesis:
		for _, sub := range e.Subjects {
			pk, err := decodeEdPub(sub.IdentityPubkey)
			if err != nil {
				return nil, fmt.Errorf("genesis subject %s: %w", sub.NodeID, err)
			}
			pks[sub.NodeID] = pk
		}
	case OpAdd:
		pk, err := decodeEdPub(e.Subject.IdentityPubkey)
		if err != nil {
			return nil, fmt.Errorf("new subject %s: %w", e.Subject.NodeID, err)
		}
		pks[e.Subject.NodeID] = pk
	case OpRemove:
		// only existing members sign
	}
	return pks, nil
}

func decodeEdPub(b64 string) (ed25519.PublicKey, error) {
	b, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, err
	}
	if len(b) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("expected %d bytes, got %d", ed25519.PublicKeySize, len(b))
	}
	return ed25519.PublicKey(b), nil
}

// Apply validates and applies an entry to the state. On error the state is
// left unchanged.
func (s *State) Apply(e *Entry) error {
	if e.Seq != s.NextSeq {
		return fmt.Errorf("seq mismatch: got %d, expected %d", e.Seq, s.NextSeq)
	}
	prev, err := hex.DecodeString(e.PrevHash)
	if err != nil {
		return fmt.Errorf("prev_hash decode: %w", err)
	}
	if !bytes.Equal(prev, s.PrevHash[:]) {
		return fmt.Errorf("prev_hash mismatch at seq=%d", e.Seq)
	}

	h, err := e.Hash()
	if err != nil {
		return err
	}

	req, err := s.RequiredApprovers(e)
	if err != nil {
		return err
	}
	pks, err := s.pubkeysForVerify(e)
	if err != nil {
		return err
	}

	for id := range req {
		sigB64, ok := e.Approvals[id]
		if !ok {
			return fmt.Errorf("missing required approval from %s", id)
		}
		if err := verifySig(pks[id], h[:], sigB64); err != nil {
			return fmt.Errorf("approval from %s: %w", id, err)
		}
	}
	// Reject signatures from unknown signers and verify any extra valid ones.
	for id, sigB64 := range e.Approvals {
		if _, isReq := req[id]; isReq {
			continue
		}
		pk, ok := pks[id]
		if !ok {
			return fmt.Errorf("approval from unknown signer: %s", id)
		}
		if err := verifySig(pk, h[:], sigB64); err != nil {
			return fmt.Errorf("extra approval from %s: %w", id, err)
		}
	}

	switch e.Op {
	case OpGenesis:
		for _, sub := range e.Subjects {
			if _, dup := s.Members[sub.NodeID]; dup {
				return fmt.Errorf("duplicate genesis member: %s", sub.NodeID)
			}
			s.Members[sub.NodeID] = sub
		}
	case OpAdd:
		if _, dup := s.Members[e.Subject.NodeID]; dup {
			return fmt.Errorf("ADD: %s already a member", e.Subject.NodeID)
		}
		s.Members[e.Subject.NodeID] = *e.Subject
	case OpRemove:
		delete(s.Members, e.Subject.NodeID)
	}
	s.NextSeq++
	s.PrevHash = h
	return nil
}

func verifySig(pk ed25519.PublicKey, msg []byte, sigB64 string) error {
	sig, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil {
		return err
	}
	if len(sig) != ed25519.SignatureSize {
		return fmt.Errorf("signature must be %d bytes, got %d", ed25519.SignatureSize, len(sig))
	}
	if !ed25519.Verify(pk, msg, sig) {
		return errors.New("invalid signature")
	}
	return nil
}
