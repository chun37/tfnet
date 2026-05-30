# tfnet

`docs/wg-evpn-l2vpn-design.md` の参照実装（Go）。

メンバーシップ台帳（Ed25519 署名チェーン + N-of-N）を single source of truth とし、
WireGuard / FRR 設定を台帳から生成する CLI。

## このリポジトリで実装する範囲

| 設計書のレイヤー                  | tfnet が担う？                                                          |
| --------------------------------- | ----------------------------------------------------------------------- |
| §3 メンバーシップ台帳（認可）     | **Yes** — 提案 / 署名収集 / 確定 / replay / 検証                        |
| §4 WireGuard トランスポート        | **設定生成のみ** — `tfnet render wg` が wg-quick 互換 conf を出力       |
| §5 VXLAN/EVPN                      | **設定生成のみ** — `tfnet render frr` が FRR 用 vtysh 互換 conf を出力 |
| §4.4 NAT ホールパンチ / リレー     | スコープ外（§8「要確定」項目）                                          |
| §5.2 VXLAN/bridge/netns の構築     | スコープ外（`ip` コマンド / systemd-networkd で別途）                  |
| §6 MTU                              | render wg の `-mtu` フラグで指定（既定 1440）                          |
| §7 BFD                              | render frr に既定で出力（300ms × 3）                                    |

## 設計書からの差分（明示）

設計書の §3.1 は `Subject` に `wg_pubkey`（Curve25519）しか持たせていないが、
台帳エントリの署名検証には Ed25519 公開鍵が必要なので、Subject に
`identity_pubkey`（Ed25519）を追加した。同一の鍵を ECDH と署名の両方に使うのは
暗号学的に好ましくないため、別の keypair として運用する。

## ビルド

```sh
go build ./...
go test ./...
```

Go 1.26 以上（`crypto/ecdh`, `log/slog` を利用）。

## 使い方（最小フロー: 2 ノードの genesis）

```sh
# 1. 各ノードで鍵を生成
tfnet keys gen-identity -node-id alice -out alice.id.json
tfnet keys gen-identity -node-id bob   -out bob.id.json
tfnet keys gen-wg -out alice.wg.json
tfnet keys gen-wg -out bob.wg.json

# 2. 公開鍵を集めて genesis 仕様を作る
cat > genesis-spec.json <<'JSON'
{
  "subjects": [
    {"node_id":"alice","identity_pubkey":"...","wg_pubkey":"...","overlay_ip":"10.99.0.1/32","endpoint":"203.0.113.1:51820"},
    {"node_id":"bob",  "identity_pubkey":"...","wg_pubkey":"...","overlay_ip":"10.99.0.2/32","endpoint":"203.0.113.2:51820"}
  ]
}
JSON

# 3. 台帳を初期化 → genesis を提案 → 全員が署名 → 確定
tfnet ledger init
tfnet ledger genesis -spec genesis-spec.json
PENDING=$(ls ledger/pending/*.json | head -1)
tfnet ledger sign -key alice.id.json "$PENDING"
tfnet ledger sign -key bob.id.json   "$PENDING"
tfnet ledger commit "$PENDING"

# 4. 各ノードで設定を生成
tfnet render wg  -self alice -wg-key alice.wg.json -listen-port 51820 -mtu 1440 -out wg0.conf
tfnet render frr -self alice -asn 65010 -out frr.conf
```

### メンバー追加（N-of-N）

```sh
tfnet ledger propose-add \
    -node-id carol \
    -identity-pubkey <carol_id_pub> \
    -wg-pubkey <carol_wg_pub> \
    -overlay-ip 10.99.0.3/32 \
    -endpoint 203.0.113.3:51820

PENDING=$(ls ledger/pending/0000*.json | sort | tail -1)

# 既存メンバー全員 + 新メンバー(carol) が署名する必要がある
tfnet ledger sign -key alice.id.json "$PENDING"
tfnet ledger sign -key bob.id.json   "$PENDING"
tfnet ledger sign -key carol.id.json "$PENDING"  # 別マシンで sign -out して collect でもよい
tfnet ledger commit "$PENDING"
```

### オフバンド署名収集（§3.5）

ペンディングファイルを USB / 別 VPN / 対面で配り、各メンバーが自分の手元で
`tfnet ledger sign -out sig.json <pending.json>` で切り離されたシグネチャを返す。
提案者が `tfnet ledger merge <pending.json> sig-alice.json sig-bob.json ...`
で集約し、揃ったら commit する。

### ステータス確認

```sh
tfnet ledger list      # コミット済みエントリ一覧
tfnet ledger members   # 現在のメンバー一覧
tfnet ledger members -json  # JSON 出力
tfnet ledger verify    # 全エントリを replay して整合性チェック
tfnet ledger show <pending.json>  # 未確定エントリの必要署名者と現状
```

## ロギングと追跡

すべての CLI 起動は `log/slog` で構造化ログを stderr（既定）または指定ファイルに出す。

```sh
tfnet -log-level debug -log-format json -log-file /var/log/tfnet.log ledger commit ...
```

加えて、台帳ディレクトリには **`audit.jsonl`** が append-only で蓄積される。
これは「誰がいつ何のエントリを提案 / 署名 / merge / commit したか」を
ハッシュ付きで永続記録するためのもので、台帳と一緒に配って事後監査に使える。

ログレベル等は **サブコマンドの前** に置く:

```sh
tfnet -log-level warn ledger commit ./ledger/pending/...
```

### 監査ログのスキーマ

各行は次の形の JSON:

```json
{
  "time": "2026-05-30T11:30:54.946Z",
  "action": "ledger.commit",
  "actor": "alice",
  "host": "node-a.example",
  "ledger_dir": "./ledger",
  "seq": 1,
  "op": "ADD",
  "target": "carol",
  "entry_hash": "1e1646408b0d...",
  "details": { "approvers": ["alice","bob","carol"] }
}
```

`action` の値:

| action                       | いつ                                                |
| ---------------------------- | --------------------------------------------------- |
| `ledger.init`                | `ledger init`                                       |
| `ledger.propose.genesis`     | `ledger genesis`                                    |
| `ledger.propose.add`         | `ledger propose-add`                                |
| `ledger.propose.remove`      | `ledger propose-remove`                             |
| `ledger.sign.inplace`        | `ledger sign` がペンディングに直接書いた時          |
| `ledger.sign.detached`       | `ledger sign -out` が独立 sig ファイルを書いた時    |
| `ledger.merge`               | `ledger merge`                                      |
| `ledger.commit`              | `ledger commit`（成功）                             |
| `ledger.commit.rejected`     | `ledger commit`（検証失敗）— `error` フィールドに理由 |
| `ledger.commit.write_failed` | `ledger commit`（log への append 失敗）            |
| `ledger.verify.ok` / `.failed` | `ledger verify`                                   |
| `render.wg` / `render.frr`   | 設定生成時                                          |

`sign` / `merge` を台帳のないマシンで実行した場合は、`audit.jsonl` への書き込みは
スキップされ slog の通常ログにだけ出る（`-ledger` で台帳ディレクトリを指してい
れば、そちらにも追記される）。

## ファイル構成

```
ledger/
├── log.jsonl       コミット済みエントリ（append-only, 1 行 1 JSON）
├── audit.jsonl     操作監査ログ（append-only, 1 行 1 JSON）
└── pending/        署名収集中のエントリ
    └── 000001-1e1646408b0d.json
```

`log.jsonl` の各行は §3.1 の Entry 構造をそのまま JSON 化したもの。エントリの
ハッシュは JSON 表現ではなく `internal/ledger` のバイナリ canonical エンコード
（big-endian seq + prev_hash + len-prefixed op + len-prefixed subject フィールド）
の SHA-256。endpoint は §3.4 に従い canonical から除外。

## やっていないこと（運用前提）

- **WireGuard の起動**: 生成された conf を `wg-quick up wg0` 等で適用する必要がある。
- **VXLAN / bridge / netns**: 設計書 §5.2, §5.4 に従い別途 `ip` コマンドや
  systemd-networkd で構築する。`tfnet` はこのレイヤーには関与しない。
- **FRR の起動**: `frr.conf` を `/etc/frr/` に置いて `vtysh -b` で読ませる。
- **NAT ホールパンチ / リレー**: §4.4・§8 の「要確定」項目。本実装にはない。
- **エンドポイントのローミング配布**: 設計書通り WireGuard 側に任せる前提。
