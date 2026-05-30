package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"tfnet/internal/keys"
)

func runKeys(args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "tfnet keys: missing subcommand (gen-identity | gen-wg | pub)")
		os.Exit(2)
	}
	switch args[0] {
	case "gen-identity":
		runKeysGenIdentity(args[1:])
	case "gen-wg":
		runKeysGenWG(args[1:])
	case "pub":
		runKeysPub(args[1:])
	default:
		die("keys: unknown subcommand %q", args[0])
	}
}

func runKeysGenIdentity(args []string) {
	fs := flag.NewFlagSet("keys gen-identity", flag.ExitOnError)
	nodeID := fs.String("node-id", "", "node identifier (required)")
	out := fs.String("out", "", "output file (required)")
	_ = fs.Parse(args)
	if *nodeID == "" || *out == "" {
		die("keys gen-identity: -node-id and -out are required")
	}
	id, err := keys.GenerateIdentity(*nodeID)
	if err != nil {
		die("generate identity: %v", err)
	}
	if err := id.Save(*out); err != nil {
		die("save identity: %v", err)
	}
	fmt.Printf("identity written: %s\n", *out)
	fmt.Printf("  node_id        : %s\n", id.NodeID)
	fmt.Printf("  identity_pubkey: %s\n", id.PublicKey)
}

func runKeysGenWG(args []string) {
	fs := flag.NewFlagSet("keys gen-wg", flag.ExitOnError)
	out := fs.String("out", "", "output file (required)")
	_ = fs.Parse(args)
	if *out == "" {
		die("keys gen-wg: -out is required")
	}
	k, err := keys.GenerateWGKey()
	if err != nil {
		die("generate wg key: %v", err)
	}
	if err := k.Save(*out); err != nil {
		die("save wg key: %v", err)
	}
	fmt.Printf("wg key written: %s\n", *out)
	fmt.Printf("  wg_pubkey: %s\n", k.PublicKey)
}

func runKeysPub(args []string) {
	fs := flag.NewFlagSet("keys pub", flag.ExitOnError)
	in := fs.String("in", "", "input key file (identity or wg) (required)")
	_ = fs.Parse(args)
	if *in == "" {
		die("keys pub: -in is required")
	}
	// Try identity first, then wg.
	if id, err := keys.LoadIdentity(*in); err == nil {
		_ = json.NewEncoder(os.Stdout).Encode(struct {
			NodeID         string `json:"node_id"`
			IdentityPubkey string `json:"identity_pubkey"`
		}{id.NodeID, id.PublicKey})
		return
	}
	k, err := keys.LoadWGKey(*in)
	if err != nil {
		die("could not parse %s as identity or wg key: %v", *in, err)
	}
	_ = json.NewEncoder(os.Stdout).Encode(struct {
		WGPubkey string `json:"wg_pubkey"`
	}{k.PublicKey})
}
