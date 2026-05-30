package main

import (
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"sort"

	"tfnet/internal/audit"
	"tfnet/internal/keys"
	"tfnet/internal/ledger"
	"tfnet/internal/tflog"
)

func runLedger(args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "tfnet ledger: missing subcommand")
		os.Exit(2)
	}
	switch args[0] {
	case "init":
		runLedgerInit(args[1:])
	case "genesis":
		runLedgerGenesis(args[1:])
	case "propose-add":
		runLedgerProposeAdd(args[1:])
	case "propose-remove":
		runLedgerProposeRemove(args[1:])
	case "sign":
		runLedgerSign(args[1:])
	case "merge":
		runLedgerMerge(args[1:])
	case "show":
		runLedgerShow(args[1:])
	case "commit":
		runLedgerCommit(args[1:])
	case "list":
		runLedgerList(args[1:])
	case "members":
		runLedgerMembers(args[1:])
	case "verify":
		runLedgerVerify(args[1:])
	default:
		die("ledger: unknown subcommand %q", args[0])
	}
}

func openStore(dir string) *ledger.Store {
	st := &ledger.Store{Dir: dir}
	if err := st.Init(); err != nil {
		die("init ledger dir %s: %v", dir, err)
	}
	return st
}

func replay(st *ledger.Store) *ledger.State {
	state, _, err := st.Replay()
	if err != nil {
		die("replay ledger: %v", err)
	}
	return state
}

// ---- init ----

func runLedgerInit(args []string) {
	fs := flag.NewFlagSet("ledger init", flag.ExitOnError)
	dir := fs.String("ledger", "", "ledger directory")
	_ = fs.Parse(args)
	st := openStore(ledgerDir(*dir))
	audit.Log(st.Dir, audit.Event{Action: "ledger.init"})
	fmt.Printf("ledger initialised at %s\n", st.Dir)
}

// ---- genesis ----
//
// A genesis spec is a JSON file describing the initial member set:
//
//   {
//     "subjects": [
//       {"node_id": "alice", "identity_pubkey": "...", "wg_pubkey": "...",
//        "overlay_ip": "10.99.0.1/32", "endpoint": "203.0.113.1:51820"},
//       ...
//     ]
//   }
//
// `tfnet ledger genesis -spec <file>` writes a pending GENESIS entry. Every
// listed subject must then `tfnet ledger sign` it before it can be committed.

type genesisSpec struct {
	Subjects []ledger.Subject `json:"subjects"`
}

func runLedgerGenesis(args []string) {
	fs := flag.NewFlagSet("ledger genesis", flag.ExitOnError)
	dir := fs.String("ledger", "", "ledger directory")
	spec := fs.String("spec", "", "JSON file listing the initial member subjects (required)")
	_ = fs.Parse(args)
	if *spec == "" {
		die("ledger genesis: -spec is required")
	}
	st := openStore(ledgerDir(*dir))
	state := replay(st)
	if state.NextSeq != 0 {
		die("ledger genesis: ledger is not empty (next seq = %d)", state.NextSeq)
	}
	b, err := os.ReadFile(*spec)
	if err != nil {
		die("read spec: %v", err)
	}
	var gs genesisSpec
	if err := json.Unmarshal(b, &gs); err != nil {
		die("parse spec: %v", err)
	}
	if len(gs.Subjects) == 0 {
		die("ledger genesis: spec has no subjects")
	}
	e := &ledger.Entry{
		Seq:       0,
		PrevHash:  ledger.ZeroHash,
		Op:        ledger.OpGenesis,
		Subjects:  gs.Subjects,
		Approvals: map[string]string{},
	}
	if _, err := e.Hash(); err != nil {
		die("invalid genesis entry: %v", err)
	}
	path, err := st.SavePending(e)
	if err != nil {
		die("save pending: %v", err)
	}
	h, _ := e.HashHex()
	subjects := make([]string, 0, len(e.Subjects))
	for _, s := range e.Subjects {
		subjects = append(subjects, s.NodeID)
	}
	sort.Strings(subjects)
	audit.Log(st.Dir, audit.Event{
		Action:    "ledger.propose.genesis",
		Seq:       audit.Seq(0),
		Op:        string(ledger.OpGenesis),
		EntryHash: h,
		Details:   map[string]any{"pending_path": path, "subjects": subjects},
	})
	fmt.Printf("genesis proposed: %s\n", path)
	printRequired(state, e)
}

// ---- propose-add ----

func runLedgerProposeAdd(args []string) {
	fs := flag.NewFlagSet("ledger propose-add", flag.ExitOnError)
	dir := fs.String("ledger", "", "ledger directory")
	nodeID := fs.String("node-id", "", "new member node_id (required)")
	idPub := fs.String("identity-pubkey", "", "new member Ed25519 identity public key, base64 (required)")
	wgPub := fs.String("wg-pubkey", "", "new member WireGuard public key, base64 (required)")
	overlay := fs.String("overlay-ip", "", "new member overlay IP, CIDR (required, e.g. 10.99.0.5/32)")
	endpoint := fs.String("endpoint", "", "optional endpoint hint (ip:port); excluded from signature")
	_ = fs.Parse(args)
	if *nodeID == "" || *idPub == "" || *wgPub == "" || *overlay == "" {
		die("ledger propose-add: -node-id, -identity-pubkey, -wg-pubkey and -overlay-ip are required")
	}
	st := openStore(ledgerDir(*dir))
	state := replay(st)
	if _, dup := state.Members[*nodeID]; dup {
		die("propose-add: %s is already a member", *nodeID)
	}
	e := &ledger.Entry{
		Seq:      state.NextSeq,
		PrevHash: hex32(state.PrevHash),
		Op:       ledger.OpAdd,
		Subject: &ledger.Subject{
			NodeID:         *nodeID,
			IdentityPubkey: *idPub,
			WGPubkey:       *wgPub,
			OverlayIP:      *overlay,
			Endpoint:       *endpoint,
		},
		Approvals: map[string]string{},
	}
	if _, err := e.Hash(); err != nil {
		die("invalid entry: %v", err)
	}
	path, err := st.SavePending(e)
	if err != nil {
		die("save pending: %v", err)
	}
	h, _ := e.HashHex()
	audit.Log(st.Dir, audit.Event{
		Action:    "ledger.propose.add",
		Seq:       audit.Seq(e.Seq),
		Op:        string(ledger.OpAdd),
		Target:    *nodeID,
		EntryHash: h,
		Details:   map[string]any{"pending_path": path, "overlay_ip": *overlay},
	})
	fmt.Printf("add proposed: %s\n", path)
	printRequired(state, e)
}

// ---- propose-remove ----

func runLedgerProposeRemove(args []string) {
	fs := flag.NewFlagSet("ledger propose-remove", flag.ExitOnError)
	dir := fs.String("ledger", "", "ledger directory")
	nodeID := fs.String("node-id", "", "member node_id to remove (required)")
	_ = fs.Parse(args)
	if *nodeID == "" {
		die("ledger propose-remove: -node-id is required")
	}
	st := openStore(ledgerDir(*dir))
	state := replay(st)
	target, ok := state.Members[*nodeID]
	if !ok {
		die("propose-remove: %s is not a member", *nodeID)
	}
	e := &ledger.Entry{
		Seq:       state.NextSeq,
		PrevHash:  hex32(state.PrevHash),
		Op:        ledger.OpRemove,
		Subject:   &target, // record the existing subject so verifiers have full context
		Approvals: map[string]string{},
	}
	if _, err := e.Hash(); err != nil {
		die("invalid entry: %v", err)
	}
	path, err := st.SavePending(e)
	if err != nil {
		die("save pending: %v", err)
	}
	h, _ := e.HashHex()
	audit.Log(st.Dir, audit.Event{
		Action:    "ledger.propose.remove",
		Seq:       audit.Seq(e.Seq),
		Op:        string(ledger.OpRemove),
		Target:    *nodeID,
		EntryHash: h,
		Details:   map[string]any{"pending_path": path},
	})
	fmt.Printf("remove proposed: %s\n", path)
	printRequired(state, e)
}

// ---- sign ----

func runLedgerSign(args []string) {
	fs := flag.NewFlagSet("ledger sign", flag.ExitOnError)
	dir := fs.String("ledger", "", "ledger directory (for audit log; optional)")
	keyPath := fs.String("key", "", "identity key file (required)")
	out := fs.String("out", "", "write a standalone signature file instead of editing the pending entry")
	_ = fs.Parse(args)
	if fs.NArg() != 1 || *keyPath == "" {
		die("usage: tfnet ledger sign -key <id.json> [-out <sig.json>] <pending.json>")
	}
	id, err := keys.LoadIdentity(*keyPath)
	if err != nil {
		die("load key: %v", err)
	}
	path := fs.Arg(0)
	e, err := ledger.LoadEntryFile(path)
	if err != nil {
		die("load entry: %v", err)
	}
	h, err := e.Hash()
	if err != nil {
		die("hash entry: %v", err)
	}
	sig, err := id.Sign(h[:])
	if err != nil {
		die("sign: %v", err)
	}
	sigB64 := base64.StdEncoding.EncodeToString(sig)
	auditDir := ledgerDirIfExists(*dir)
	tflog.Info("sign", "node_id", id.NodeID, "entry_hash", hex32(h), "pending", path)
	if *out != "" {
		s := struct {
			NodeID    string `json:"node_id"`
			EntryHash string `json:"entry_hash"`
			Signature string `json:"signature"`
		}{id.NodeID, hex32(h), sigB64}
		b, _ := json.MarshalIndent(s, "", "  ")
		if err := os.WriteFile(*out, append(b, '\n'), 0o600); err != nil {
			die("write %s: %v", *out, err)
		}
		audit.Log(auditDir, audit.Event{
			Action:    "ledger.sign.detached",
			Actor:     id.NodeID,
			EntryHash: hex32(h),
			Details:   map[string]any{"sig_path": *out, "pending_path": path},
		})
		fmt.Printf("signature written: %s\n", *out)
		return
	}
	if e.Approvals == nil {
		e.Approvals = map[string]string{}
	}
	if existing, ok := e.Approvals[id.NodeID]; ok && existing == sigB64 {
		fmt.Printf("already signed by %s; no change\n", id.NodeID)
		return
	}
	e.Approvals[id.NodeID] = sigB64
	if err := ledger.SaveEntryFile(path, e); err != nil {
		die("write %s: %v", path, err)
	}
	audit.Log(auditDir, audit.Event{
		Action:    "ledger.sign.inplace",
		Actor:     id.NodeID,
		EntryHash: hex32(h),
		Details:   map[string]any{"pending_path": path},
	})
	fmt.Printf("signed %s as %s\n", path, id.NodeID)
}

// ---- merge ----

func runLedgerMerge(args []string) {
	fs := flag.NewFlagSet("ledger merge", flag.ExitOnError)
	dir := fs.String("ledger", "", "ledger directory (for audit log; optional)")
	_ = fs.Parse(args)
	if fs.NArg() < 2 {
		die("usage: tfnet ledger merge [-ledger DIR] <pending.json> <sig.json> [<sig.json>...]")
	}
	path := fs.Arg(0)
	e, err := ledger.LoadEntryFile(path)
	if err != nil {
		die("load entry: %v", err)
	}
	h, err := e.HashHex()
	if err != nil {
		die("hash entry: %v", err)
	}
	if e.Approvals == nil {
		e.Approvals = map[string]string{}
	}
	auditDir := ledgerDirIfExists(*dir)
	var merged []string
	for _, sp := range fs.Args()[1:] {
		b, err := os.ReadFile(sp)
		if err != nil {
			die("read %s: %v", sp, err)
		}
		var s struct {
			NodeID    string `json:"node_id"`
			EntryHash string `json:"entry_hash"`
			Signature string `json:"signature"`
		}
		if err := json.Unmarshal(b, &s); err != nil {
			die("parse %s: %v", sp, err)
		}
		if s.NodeID == "" || s.Signature == "" {
			die("%s: missing node_id or signature", sp)
		}
		if s.EntryHash != "" && s.EntryHash != h {
			die("%s: entry_hash mismatch (sig is for a different entry)", sp)
		}
		e.Approvals[s.NodeID] = s.Signature
		merged = append(merged, s.NodeID)
		fmt.Printf("merged signature from %s\n", s.NodeID)
	}
	if err := ledger.SaveEntryFile(path, e); err != nil {
		die("write %s: %v", path, err)
	}
	audit.Log(auditDir, audit.Event{
		Action:    "ledger.merge",
		EntryHash: h,
		Details:   map[string]any{"pending_path": path, "merged_from": merged},
	})
}

// ---- show ----

func runLedgerShow(args []string) {
	fs := flag.NewFlagSet("ledger show", flag.ExitOnError)
	dir := fs.String("ledger", "", "ledger directory")
	_ = fs.Parse(args)
	if fs.NArg() != 1 {
		die("usage: tfnet ledger show [-ledger DIR] <pending.json>")
	}
	st := openStore(ledgerDir(*dir))
	state := replay(st)
	e, err := ledger.LoadEntryFile(fs.Arg(0))
	if err != nil {
		die("load entry: %v", err)
	}
	h, err := e.HashHex()
	if err != nil {
		die("hash entry: %v", err)
	}
	fmt.Printf("entry_hash: %s\n", h)
	fmt.Printf("seq:        %d\n", e.Seq)
	fmt.Printf("op:         %s\n", e.Op)
	fmt.Printf("prev_hash:  %s\n", e.PrevHash)
	printRequired(state, e)
	if len(e.Approvals) > 0 {
		fmt.Println("approvals (already collected):")
		ids := make([]string, 0, len(e.Approvals))
		for id := range e.Approvals {
			ids = append(ids, id)
		}
		sort.Strings(ids)
		for _, id := range ids {
			fmt.Printf("  - %s\n", id)
		}
	}
}

// ---- commit ----

func runLedgerCommit(args []string) {
	fs := flag.NewFlagSet("ledger commit", flag.ExitOnError)
	dir := fs.String("ledger", "", "ledger directory")
	keep := fs.Bool("keep-pending", false, "do not delete pending file after commit")
	_ = fs.Parse(args)
	if fs.NArg() != 1 {
		die("usage: tfnet ledger commit [-ledger DIR] <pending.json>")
	}
	st := openStore(ledgerDir(*dir))
	state := replay(st)
	path := fs.Arg(0)
	e, err := ledger.LoadEntryFile(path)
	if err != nil {
		die("load entry: %v", err)
	}
	h, _ := e.HashHex()
	target := ""
	if e.Subject != nil {
		target = e.Subject.NodeID
	}
	if err := state.Apply(e); err != nil {
		audit.Log(st.Dir, audit.Event{
			Action:    "ledger.commit.rejected",
			Seq:       audit.Seq(e.Seq),
			Op:        string(e.Op),
			Target:    target,
			EntryHash: h,
			Error:     err.Error(),
			Details:   map[string]any{"pending_path": path},
		})
		die("validate: %v", err)
	}
	if err := st.Append(e); err != nil {
		audit.Log(st.Dir, audit.Event{
			Action:    "ledger.commit.write_failed",
			Seq:       audit.Seq(e.Seq),
			Op:        string(e.Op),
			Target:    target,
			EntryHash: h,
			Error:     err.Error(),
		})
		die("append to log: %v", err)
	}
	if !*keep {
		_ = os.Remove(path)
	}
	approvers := make([]string, 0, len(e.Approvals))
	for id := range e.Approvals {
		approvers = append(approvers, id)
	}
	sort.Strings(approvers)
	audit.Log(st.Dir, audit.Event{
		Action:    "ledger.commit",
		Seq:       audit.Seq(e.Seq),
		Op:        string(e.Op),
		Target:    target,
		EntryHash: h,
		Details: map[string]any{
			"approvers":    approvers,
			"pending_path": path,
		},
	})
	fmt.Printf("committed seq=%d op=%s\n", e.Seq, e.Op)
}

// ---- list ----

func runLedgerList(args []string) {
	fs := flag.NewFlagSet("ledger list", flag.ExitOnError)
	dir := fs.String("ledger", "", "ledger directory")
	_ = fs.Parse(args)
	st := openStore(ledgerDir(*dir))
	entries, err := st.LoadEntries()
	if err != nil {
		die("load: %v", err)
	}
	for _, e := range entries {
		h, _ := e.HashHex()
		switch e.Op {
		case ledger.OpGenesis:
			ids := make([]string, 0, len(e.Subjects))
			for _, s := range e.Subjects {
				ids = append(ids, s.NodeID)
			}
			sort.Strings(ids)
			fmt.Printf("seq=%d %s subjects=%v hash=%s\n", e.Seq, e.Op, ids, h[:16])
		default:
			fmt.Printf("seq=%d %s %s hash=%s\n", e.Seq, e.Op, e.Subject.NodeID, h[:16])
		}
	}
}

// ---- members ----

func runLedgerMembers(args []string) {
	fs := flag.NewFlagSet("ledger members", flag.ExitOnError)
	dir := fs.String("ledger", "", "ledger directory")
	asJSON := fs.Bool("json", false, "output as JSON")
	_ = fs.Parse(args)
	st := openStore(ledgerDir(*dir))
	state := replay(st)
	ids := state.MemberIDs()
	if *asJSON {
		out := make([]ledger.Subject, 0, len(ids))
		for _, id := range ids {
			out = append(out, state.Members[id])
		}
		_ = json.NewEncoder(os.Stdout).Encode(out)
		return
	}
	for _, id := range ids {
		m := state.Members[id]
		fmt.Printf("%-20s overlay=%-18s wg=%s endpoint=%s\n",
			m.NodeID, m.OverlayIP, m.WGPubkey, m.Endpoint)
	}
}

// ---- verify ----

func runLedgerVerify(args []string) {
	fs := flag.NewFlagSet("ledger verify", flag.ExitOnError)
	dir := fs.String("ledger", "", "ledger directory")
	_ = fs.Parse(args)
	st := openStore(ledgerDir(*dir))
	state, entries, err := st.Replay()
	if err != nil {
		audit.Log(st.Dir, audit.Event{
			Action: "ledger.verify.failed",
			Error:  err.Error(),
		})
		die("verify: %v", err)
	}
	audit.Log(st.Dir, audit.Event{
		Action: "ledger.verify.ok",
		Details: map[string]any{
			"entries":  len(entries),
			"members":  len(state.Members),
			"next_seq": state.NextSeq,
		},
	})
	fmt.Printf("OK: %d entries, %d current members, next seq=%d\n",
		len(entries), len(state.Members), state.NextSeq)
}

// ---- helpers ----

func printRequired(state *ledger.State, e *ledger.Entry) {
	miss, err := state.MissingApprovers(e)
	if err != nil {
		fmt.Printf("(required approvers unknown: %v)\n", err)
		return
	}
	req, _ := state.RequiredApprovers(e)
	all := make([]string, 0, len(req))
	for id := range req {
		all = append(all, id)
	}
	sort.Strings(all)
	fmt.Printf("required approvers: %v\n", all)
	if len(miss) > 0 {
		fmt.Printf("still missing:      %v\n", miss)
	} else {
		fmt.Printf("all approvals present -- ready to commit\n")
	}
}

// ledgerDirIfExists returns the resolved ledger directory only when the
// directory already exists. Used by `sign` / `merge` which can run on
// machines that don't host a ledger (the signer just signs a hash) — in
// that case audit.Log still emits via slog but skips the file write.
func ledgerDirIfExists(dirFlag string) string {
	d := ledgerDir(dirFlag)
	if d == "" {
		return ""
	}
	if fi, err := os.Stat(d); err == nil && fi.IsDir() {
		return d
	}
	return ""
}

func hex32(h [32]byte) string {
	const hexdigits = "0123456789abcdef"
	out := make([]byte, 64)
	for i, b := range h {
		out[i*2] = hexdigits[b>>4]
		out[i*2+1] = hexdigits[b&0xf]
	}
	return string(out)
}
