# tfnet

`docs/wg-evpn-l2vpn-design.md` の参照実装（Go）。

メンバーシップ台帳（Ed25519 署名チェーン + N-of-N）を single source of truth とし、
WireGuard / FRR 設定を台帳から生成する CLI。

## このリポジトリで実装する範囲

| 設計書のレイヤー                   | tfnet が担う？                                                                  |
| ---------------------------------- | ------------------------------------------------------------------------------- |
| §3 メンバーシップ台帳（認可）       | **Yes** — 提案 / 署名収集 / 確定 / replay / 検証                                |
| §4 WireGuard トランスポート          | **Yes** — `tfnet start` が wg-quick で up/down、生成 conf も同時に書き出す      |
| §5 VXLAN/EVPN/bridge                | **Yes** — `tfnet start` が `ip link` + `bridge` + FRR reload を冪等に実行       |
| §4.4 NAT ホールパンチ / リレー       | スコープ外（§8「要確定」項目、シグナリングプロトコル未定）                       |
| §5.4 network namespace 分離         | スコープ外（推奨仕様だが本実装は root netns 前提。後日 `-netns` で拡張予定）    |
| §6 MTU                               | `-wg-mtu` / `-overlay-mtu` で指定（既定 1440 / 1390 = wg-mtu - 50）             |
| §7 BFD                               | render/start とも既定で出力（300ms × 3）                                        |
| 依存パッケージのインストール          | `setup.sh`（apt/dnf/pacman 対応、FRR の bgpd/bfdd 有効化、モジュール永続化）   |
| systemd 統合                          | `contrib/tfnet@.service` テンプレート（`tfnet@<node_id>.service`）             |

## 設計書からの差分（明示）

設計書の §3.1 は `Subject` に `wg_pubkey`（Curve25519）しか持たせていないが、
台帳エントリの署名検証には Ed25519 公開鍵が必要なので、Subject に
`identity_pubkey`（Ed25519）を追加した。同一の鍵を ECDH と署名の両方に使うのは
暗号学的に好ましくないため、別の keypair として運用する。

## セットアップ

依存パッケージの導入とビルドはまとめて `setup.sh` で:

```sh
./setup.sh                 # 依存インストール + ./tfnet をビルド
INSTALL=1 ./setup.sh       # 加えて /usr/local/bin/tfnet にインストール
SYSTEMD=1 ./setup.sh       # 加えて contrib/tfnet@.service を /etc/systemd/system に配置
```

これがやること:

- `wireguard` / `wireguard-tools` / `frr` / `frr-pythontools` / `iproute2` / `jq` を導入
- `/etc/frr/daemons` で `bgpd` と `bfdd` を有効化し FRR を再起動
- `wireguard` と `vxlan` カーネルモジュールをロード + `/etc/modules-load.d/tfnet.conf` で永続化
- `go build -o tfnet ./cmd/tfnet`

開発時はこの手前で:

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

# 4a. (確認用) 設定ファイルを手で見たい場合
tfnet render wg  -self alice -wg-key alice.wg.json -listen-port 51820 -mtu 1440 -out wg0.conf
tfnet render frr -self alice -asn 65010 -out frr.conf

# 4b. (本番) 一発で wg/vxlan/bridge/FRR を立ち上げる
sudo tfnet start -self alice -wg-key alice.wg.json -listen-port 51820 -asn 65010
sudo tfnet status -self alice
sudo tfnet stop -self alice
```

## start / stop / status

`tfnet start` は台帳と自分の wg 鍵から:

1. WireGuard conf を `/etc/wireguard/<wg-iface>.conf` に書き出して `wg-quick up`
2. VXLAN デバイスを作成（`type vxlan id <VNI> dstport 4789 local <self_overlay> nolearning`）
3. ブリッジを作成し VXLAN を attach
4. §5.2 のブリッジ設定（`bridge link set ... neigh_suppress on learning off`）
5. MTU を §6.1 に従い設定（wg=1440, vxlan/bridge=1390）
6. FRR conf を書き出して `systemctl reload-or-restart frr`

までを冪等に実行します。既に立っているインターフェースは作り直さず、wg のピア
変更は `wg syncconf` でホットリロードします。

`tfnet stop` は逆順:

1. `vtysh` で `no router bgp <ASN>` / `no bfd` を流し FRR の該当セッションだけを除去
2. VXLAN / bridge / wg 各インターフェースを削除

`tfnet status` は `wg show <iface> dump` と `vtysh -c "show bgp l2vpn evpn summary"` を使って、
ピアのハンドシェイク時刻・転送量・BGP/EVPN セッション状態を一覧表示します。

### よく使うフラグ

| フラグ              | 既定値                       | 説明                                       |
| ------------------- | ---------------------------- | ------------------------------------------ |
| `-self <id>`        | （必須: start, status）       | このホストの node_id                       |
| `-wg-key <file>`    | （必須: start）              | wg 秘密鍵 JSON（`keys gen-wg` の出力）     |
| `-ledger <dir>`     | `$TFNET_LEDGER` か `./ledger` | 台帳ディレクトリ                           |
| `-asn <n>`          | `65010`                      | iBGP プライベート ASN                       |
| `-wg-iface <name>`  | `tfnet0`                     | WireGuard インターフェース名                |
| `-vxlan-iface`      | `tfvx0`                      | VXLAN デバイス名                            |
| `-bridge-iface`     | `tfbr0`                      | ブリッジ名                                  |
| `-vni <n>`          | `10000`                      | VXLAN VNI                                   |
| `-wg-mtu <n>`       | `1440`                       | wg インターフェース MTU（§6）              |
| `-overlay-mtu <n>`  | `wg-mtu - 50`                | vxlan/bridge MTU                            |
| `-listen-port <n>`  | エフェメラル                   | WireGuard ListenPort                        |
| `-skip-frr`         | `false`                      | FRR を触らない（wg + vxlan のみ）           |
| `-dry-run`          | `false`                      | 全コマンドをログに出すだけで実行しない        |

### dry-run

`-dry-run` を付けると、書き込もうとしているファイル・実行しようとしている
`ip` / `wg-quick` / `bridge` / `systemctl` / `vtysh` のコマンドが全て slog に出ます。
root 権限がない環境で出力を眺めるのに便利:

```sh
tfnet start -self alice -wg-key alice.wg.json -dry-run
```

### systemd で常駐させる

```sh
SYSTEMD=1 ./setup.sh
sudo cp contrib/tfnet.env.example /etc/default/tfnet
sudo vi /etc/default/tfnet              # TFNET_OPTS を編集
sudo systemctl enable --now tfnet@alice
sudo systemctl status  tfnet@alice
```

`%i`（インスタンス名）が `-self` に渡されるので、`tfnet@alice.service` /
`tfnet@bob.service` のように node_id ごとにユニットを起動できる。

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

- **NAT ホールパンチ / リレー**: §4.4・§8 の「要確定」項目。シグナリングプロトコルが未確定なので未実装。
  当面は A 区分（グローバル IP を持つノード）間または A-B（B が A へ発呼）のみ繋がる前提。
- **network namespace 分離**: 設計書 §5.4 は推奨だが、wg-quick の netns サポートが限定的なので
  root netns 前提とした。将来 `-netns` フラグで拡張する余地は残している。
- **エンドポイントのローミング配布**: 設計書通り WireGuard 側に任せる（`endpoint` は §3.4 に従い署名対象外）。
