# 台帳署名のシーケンス図

[wg-evpn-l2vpn-design.md §3](./wg-evpn-l2vpn-design.md#3-メンバーシップ台帳認可レイヤー) で
規定されている N-of-N 署名フローを、本実装（GitHub を配信経路、`tfnet sync` で各ホスト
が定期的に pull する構成）に即した形で図解する。

凡例:

- `h = SHA256(canonical(entry))` — エントリのバイナリ canonical 形式の SHA-256
- `Ed25519_sign(priv, h)` — Ed25519 で `h` に署名
- `M_before` / `M_after` — そのエントリ適用前後のメンバー集合

---

## 1. メンバー追加 (ADD)

新メンバー carol を、既存メンバー alice / bob のいる台帳に加える例。
必要署名者 = `M_after = M_before ∪ {carol} = {alice, bob, carol}`（**新メンバーも自分の
参加に同意する署名が必要**）。

本実装では **新参 carol が自分の参加提案を自分で push する** フローを既定とする
（`tfnet ledger propose-self-add`）。公開鍵を既存メンバーに送って転記してもらう
ハンドオフが不要になり、`identity_pubkey` の取り違え事故も起こらない。代理提案
（`propose-add`）の経路も残してあるので、carol が push 権限を持たない場合は
既存メンバーが代行できる（下の補足を参照）。

```mermaid
sequenceDiagram
    autonumber
    actor C as carol<br/>(新参)
    actor A as alice<br/>(既存)
    actor B as bob<br/>(既存)
    participant R as GitHub<br/>(private repo)

    Note over C: tfnet keys gen-identity<br/>tfnet keys gen-wg<br/>(秘密鍵はローカルのみ)

    rect rgb(240, 245, 255)
        Note over C: --- 提案フェーズ (carol 主導) ---
        C->>R: git clone
        C->>C: tfnet ledger propose-self-add<br/>-id-key carol.id.json<br/>-wg-key carol.wg.json<br/>-overlay-ip 10.99.0.3/32
        Note over C: 鍵ファイルから node_id /<br/>identity_pubkey / wg_pubkey を抽出<br/>→ entry = {seq, prev_hash,<br/>op=ADD, subject=carol}<br/>→ pending/0003-1e16/entry.json<br/>同じ識別鍵で自署も同時に書く<br/>→ sigs/carol.json
        C->>R: git push
    end

    rect rgb(240, 255, 240)
        Note over A,B: --- 承認フェーズ (並列 OK) ---
        par alice
            A->>R: tfnet ledger approve (内部で git pull)
            Note over A: 同じ h を独立計算<br/>sig = Ed25519_sign(alice_priv, h)<br/>→ sigs/alice.json
            A->>R: git push
        and bob
            B->>R: tfnet ledger approve
            Note over B: → sigs/bob.json
            B->>R: git push
        end
        Note over R: 各員のファイルは別パス<br/>→ merge 衝突なし
    end

    rect rgb(255, 250, 240)
        Note over A,B: --- 確定フェーズ ---
        Note over A,B: 最後に approve した側が<br/>必要署名揃ったことを検知して<br/>そのまま ledger-commit + push<br/>(approve の -no-finalize で抑制可)
        A->>R: tfnet ledger commit (auto)
        Note over A: 1. h を再計算 (改竄検出)<br/>2. 必要署名者集合 R を導出<br/>3. ∀id ∈ R: ed25519.Verify(pk_id, h, sig_id)<br/>4. log.jsonl に append, pending/ を削除
        A->>R: git push
    end

    rect rgb(255, 240, 240)
        Note over B,C: --- 反映フェーズ (systemd timer) ---
        B->>R: tfnet sync (git pull --ff-only)
        Note over B: hooks.d/10-restart-tfnet.sh が<br/>TFNET_ADDED=carol を受けて<br/>tfnet start を再実行<br/>→ wg syncconf で carol を追加
        C->>R: tfnet sync
        Note over C: 初回 tfnet start で<br/>overlay に参加
    end
```

> **代理提案ルート (`propose-add`) を取るとき**: carol に push 権限を渡さない／carol の手元に
> tfnet を入れたくない場合は、既存メンバーが `tfnet ledger propose-add -node-id ... -identity-pubkey ...
> -wg-pubkey ... -overlay-ip ...` で代行する。carol は別経路（`tfnet ledger sign -out` で出した
> detached 署名ファイル）を Slack 等で送り、提案者が `tfnet ledger merge` で取り込む。
> 安全性は同じ（commit 時に N-of-N の署名検証は同様に走る）。

---

## 2. メンバー削除 (REMOVE)

carol を退去させる例。必要署名者 = `M_before \ {carol} = {alice, bob}`（**退去対象自身
は署名しない**）。

```mermaid
sequenceDiagram
    autonumber
    actor A as alice<br/>(提案者)
    actor B as bob
    actor C as carol<br/>(退去対象)
    participant R as GitHub

    A->>A: tfnet ledger propose-remove -node-id carol
    Note over A: entry = {seq, op=REMOVE,<br/>subject=carol}
    A->>A: sign → sigs/alice.json
    A->>R: git push

    B->>R: git pull
    B->>B: sign → sigs/bob.json
    B->>R: git push

    Note over A,C: carol の署名は不要 (M_after から外れるため)<br/>仮に carol が sigs/carol.json を追加しても<br/>commit 時の "unknown signer" 検査で reject

    A->>R: git pull
    A->>A: tfnet ledger commit
    Note over A: 必要署名者 = {alice, bob}<br/>= M_before \ {carol}<br/>2 つ揃った → log.jsonl に追記
    A->>R: git push

    C->>R: tfnet sync
    Note over C: 自分が REMOVE されたことを<br/>TFNET_REMOVED=carol で知る<br/>(以降 peer 全員から到達不能)
```

---

## 3. Genesis (初期ブートストラップ)

`seq=0` の特別ケース。`M_before = {}` から始まり、必要署名者 = `subjects` 全員。
`prev_hash` は `0x00…00`。

```mermaid
sequenceDiagram
    autonumber
    actor A as alice<br/>(提案者)
    actor B as bob
    participant R as GitHub<br/>(空 repo)

    Note over A,B: 各自で keys gen-identity / gen-wg
    A-->>B: 公開鍵交換 (任意経路)
    B-->>A: 公開鍵交換 (任意経路)

    A->>A: tfnet ledger init<br/>tfnet ledger genesis -spec genesis-spec.json
    Note over A: entry = {seq=0,<br/>prev_hash=0x00..00,<br/>op=GENESIS,<br/>subjects=[alice, bob]}
    A->>A: sign → sigs/alice.json
    A->>R: git push

    B->>R: git pull
    B->>B: sign → sigs/bob.json
    B->>R: git push

    A->>R: git pull
    A->>A: tfnet ledger commit
    Note over A: 必要署名者 = subjects = {alice, bob}<br/>seq=0 のみ許可<br/>identity_pubkey は entry.subjects から取得<br/>(まだ Members map が空のため)
    A->>R: git push
```

---

## 4. commit 時の検証 (拡大図)

`tfnet ledger commit <pending_dir>` が内部で行う一連の検査。**一つでも失敗すれば
状態は一切変更されない**（all-or-nothing）。

```mermaid
sequenceDiagram
    autonumber
    participant CLI as tfnet ledger commit
    participant FS as ファイルシステム
    participant E as Entry (in-memory)
    participant ST as State (replay 済み)

    CLI->>FS: read pending_dir/entry.json
    CLI->>FS: read every pending_dir/sigs/*.json
    CLI->>E: merge into Approvals map<br/>(node_id → base64 sig)
    CLI->>CLI: h_local = SHA256(canonical(entry))

    loop for each sig in sigs/
        CLI->>CLI: sig.entry_hash == h_local ?
        Note over CLI: 不一致 → reject<br/>(別 entry 向け sig の流用防止)
    end

    CLI->>ST: state.Apply(entry)
    activate ST

    ST->>ST: seq == state.next_seq ?
    ST->>ST: prev_hash == state.prev_hash ?
    Note over ST: chain 整合性チェック

    ST->>ST: required = RequiredApprovers(entry)
    Note over ST: GENESIS: subjects 全員<br/>ADD: M_before ∪ {new}<br/>REMOVE: M_before \ {target}

    loop ∀ id ∈ required
        ST->>ST: pk_id = lookup_pubkey(id)
        Note over ST: ADD/REMOVE: state.Members から<br/>GENESIS: entry.subjects から<br/>(初回は Members が空のため)
        ST->>ST: ed25519.Verify(pk_id, h_local, sigs[id])
        Note over ST: 失敗 → reject<br/>欠落 → "missing required approval"
    end

    loop ∀ id ∈ entry.Approvals \ required
        ST->>ST: 既知メンバーの sig か?
        Note over ST: 未知の署名者 → reject<br/>(noise 注入を排除)
    end

    Note over ST: ここまで全部通れば適用
    ST->>ST: ADD: Members[s.id] = s<br/>REMOVE: delete Members[s.id]<br/>GENESIS: Members[s.id] = s ∀ s
    ST->>ST: state.next_seq++<br/>state.prev_hash = h_local

    deactivate ST

    CLI->>FS: append entry to log.jsonl
    CLI->>FS: remove pending_dir/
```

---

## 補足: なぜ "sig.entry_hash == h_local" の検査が要るか

各 `sigs/<node>.json` は実は `entry_hash` フィールドを持っている。これは
entry.json が差し替えられた場合の **早期検出** 用。

攻撃シナリオ:

1. 攻撃者が `entry.json` を書き換えて push（subject.overlay_ip を別 IP に）
2. 古い sig は新しい h に対しては Ed25519.Verify が当然失敗する
3. しかしエラーメッセージが "invalid signature" になり、原因究明が遠回りになる

`sig.entry_hash` を先に比較すれば、即座に「sig は別のエントリ用」と特定できて
ログが読みやすい。**安全性は ed25519 検証だけで十分**（hash 比較は便宜上の
fail-fast に過ぎない）。
