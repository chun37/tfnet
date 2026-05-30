# tfnet

`docs/wg-evpn-l2vpn-design.md` の参照実装（Go）。

メンバーシップ台帳（Ed25519 署名チェーン + N-of-N）を single source of truth とし、
そこから WireGuard / FRR の設定を生成して `wg-quick` + `ip link` + FRR を駆動する CLI。
台帳の配信は **プライベート GitHub repo** を経路にし、各ホストは `tfnet sync` を
systemd timer で回して変更を検知 → ユーザ定義フックを発火、という構成を想定。

## 全体図

```
                ┌─────────────────────────────────────────┐
                │  Private GitHub repo (ledger only)      │
                │    ledger/log.jsonl                     │
                │    ledger/pending/<seq>-<hash>/         │
                │       entry.json                        │
                │       sigs/<node_id>.json   (each       │
                │       sigs/...                signer    │
                │                               appends)  │
                └────────────┬────────────────────────────┘
                git push     │  git pull --ff-only
                             │  (systemd timer: tfnet sync)
              ┌──────────────┼──────────────┐
              ▼              ▼              ▼
        ┌──────────┐   ┌──────────┐   ┌──────────┐
        │  alice   │   │   bob    │   │  carol   │  host
        ├──────────┤   ├──────────┤   ├──────────┤
        │ tfnet    │   │ tfnet    │   │ tfnet    │  CLI
        │ wg-quick │   │ wg-quick │   │ wg-quick │  data plane
        │ FRR(bgpd)│   │ FRR(bgpd)│   │ FRR(bgpd)│  control plane
        └──────────┘   └──────────┘   └──────────┘
            ▲             ▲             ▲
            └─── WireGuard full-mesh ───┘   (overlay carries iBGP + VXLAN)
```

ローカルに残る秘密情報（**絶対に repo に入れない**）:

| ファイル              | 中身                                                       |
| --------------------- | ---------------------------------------------------------- |
| `<node>.id.json`      | Ed25519 identity 秘密鍵（提案・承認の署名に使う）           |
| `<node>.wg.json`      | WireGuard X25519 秘密鍵                                    |
| `audit.jsonl`         | このホストの操作監査ログ（既定 `/var/log/tfnet/audit.jsonl`） |

repo に入るもの: `ledger/log.jsonl` と `ledger/pending/*/` のみ。

## 実装範囲

| 設計書のレイヤー                   | tfnet                                                                           |
| ---------------------------------- | ------------------------------------------------------------------------------- |
| §3 メンバーシップ台帳（認可）       | 提案 / 署名収集 / 確定 / replay / 検証                                          |
| §3.5 オフバンド署名収集             | `tfnet sync`（GitHub 経由）と `-out` 付き手動配布の両方をサポート              |
| §4 WireGuard トランスポート          | `tfnet start` が `wg-quick` で up/down、変更時は `wg syncconf` でホットリロード |
| §5 VXLAN/EVPN/bridge                | `tfnet start` が `ip link` + `bridge` + FRR reload を冪等に実行                |
| §6 MTU                               | `-wg-mtu` / `-overlay-mtu` で指定（既定 1440 / 1390 = wg-mtu - 50）             |
| §7 BFD                               | FRR conf に既定で出力（300ms × 3）                                              |
| §4.4 NAT ホールパンチ/リレー        | スコープ外（§8 要確定）                                                          |
| §5.4 netns 分離                      | スコープ外（root netns 前提、将来拡張）                                         |

## 設計書からの差分（明示）

設計書 §3.1 の Subject は `wg_pubkey`（Curve25519）しか持たないが、台帳エントリの
署名検証には Ed25519 公開鍵が必要なので Subject に `identity_pubkey`（Ed25519）を
追加した。同一の鍵を ECDH と署名の両方に使うのは暗号学的に好ましくないため、
別 keypair として運用する。

---

## セットアップ

```sh
./setup.sh                 # 依存インストール + ./tfnet をビルド
INSTALL=1 ./setup.sh       # 加えて /usr/local/bin/tfnet にインストール
SYSTEMD=1 ./setup.sh       # 加えて systemd ユニットを /etc/systemd/system に配置
```

`setup.sh` がやること:

- `wireguard` / `wireguard-tools` / `frr` / `frr-pythontools` / `iproute2` / `git` / `jq` を導入
- `/etc/frr/daemons` で `bgpd` と `bfdd` を有効化し FRR を再起動
- `wireguard` / `vxlan` カーネルモジュールをロードし `/etc/modules-load.d/tfnet.conf` で永続化
- `go build -o tfnet ./cmd/tfnet`
- `SYSTEMD=1` 時: `tfnet@.service` と `tfnet-sync.{service,timer}` を配置、サンプルフックを `/usr/share/tfnet/hooks.d.example/` にコピー、`/etc/tfnet/hooks.d/` を作成

開発時は `go build ./... && go test ./...` で十分。Go 1.26+ 必須。

---

## ブートストラップ（最初のメンバー数人で台帳を立てる）

「闇ネット」を立ち上げる alice と bob を例に。GitHub に **空の private repo**
（例 `git@github.com:our-org/tfnet-ledger.git`）を作っておく。

### 1. 各ノードで鍵を生成（ローカルに保管、共有しない）

```sh
# alice の手元
tfnet keys gen-identity -node-id alice -out /etc/tfnet/alice.id.json
tfnet keys gen-wg                       -out /etc/tfnet/alice.wg.json
```

```sh
# bob の手元
tfnet keys gen-identity -node-id bob   -out /etc/tfnet/bob.id.json
tfnet keys gen-wg                       -out /etc/tfnet/bob.wg.json
```

### 2. 公開鍵を集めて genesis 仕様を作る（提案者 alice）

bob は自分の identity と wg の **公開鍵だけ** を alice に渡す:

```sh
# bob: 公開鍵のみを出力（秘密鍵は手元に残る）
tfnet keys pub -in /etc/tfnet/bob.id.json
tfnet keys pub -in /etc/tfnet/bob.wg.json
```

alice はそれを使って genesis spec を作る:

```sh
cat > /tmp/genesis-spec.json <<'JSON'
{
  "subjects": [
    {"node_id":"alice","identity_pubkey":"<alice-id-pub>","wg_pubkey":"<alice-wg-pub>","overlay_ip":"10.99.0.1/32","endpoint":"203.0.113.1:51820"},
    {"node_id":"bob",  "identity_pubkey":"<bob-id-pub>",  "wg_pubkey":"<bob-wg-pub>",  "overlay_ip":"10.99.0.2/32","endpoint":"203.0.113.2:51820"}
  ]
}
JSON
```

### 3. ローカルに repo をクローンし、台帳を初期化

```sh
# alice の手元
sudo mkdir -p /var/lib/tfnet
sudo chown $USER /var/lib/tfnet
cd /var/lib/tfnet
git clone git@github.com:our-org/tfnet-ledger.git repo
cd repo
tfnet ledger init                          # ./ledger/ ができる
tfnet ledger genesis -spec /tmp/genesis-spec.json
# -> ledger/pending/000000-<hash>/entry.json と sigs/ が生成される
```

### 4. alice が自分の署名を入れて push

```sh
tfnet ledger sign -key /etc/tfnet/alice.id.json ledger/pending/000000-*/
# -> ledger/pending/000000-*/sigs/alice.json が追加される

git add ledger && git commit -m "propose genesis" && git push
```

### 5. bob がクローン → 署名 → push

```sh
# bob の手元
cd /var/lib/tfnet
git clone git@github.com:our-org/tfnet-ledger.git repo
cd repo
tfnet ledger sign -key /etc/tfnet/bob.id.json ledger/pending/000000-*/
# -> ledger/pending/000000-*/sigs/bob.json が追加される

git add ledger && git commit -m "bob signs genesis" && git push
```

**衝突しない**: alice の `sigs/alice.json` と bob の `sigs/bob.json` は別ファイル。

### 6. alice が pull → commit → push

```sh
# alice の手元
cd /var/lib/tfnet/repo
git pull --ff-only
tfnet ledger show ledger/pending/000000-*/
# "all approvals present -- ready to commit"

tfnet ledger commit ledger/pending/000000-*/
# -> ledger/log.jsonl に append、pending/ ディレクトリは消える

git add ledger && git commit -m "commit genesis" && git push
```

### 7. 両ノードで sync + start

```sh
# alice / bob の両方で
sudo tfnet sync -repo /var/lib/tfnet/repo -self <name>
sudo tfnet start -self <name> -wg-key /etc/tfnet/<name>.wg.json -ledger /var/lib/tfnet/repo/ledger
sudo tfnet status -self <name>
```

→ 闇ネット稼働。以降の sync は systemd timer に任せる（後述）。

---

## メンバー追加: carol の参加（三者視点）

既存メンバー alice / bob と、新参 carol。carol は **既に repo へ push できる
GitHub アカウント** を持っているとする（branch protection で main 直 push を禁止し、
PR レビューで承認する運用もあり）。

### carol の手元

```sh
# 1. 鍵生成
tfnet keys gen-identity -node-id carol -out /etc/tfnet/carol.id.json
tfnet keys gen-wg                       -out /etc/tfnet/carol.wg.json

# 2. 公開情報を提案者に渡す（メール / Slack / 何でもいい — 信頼性不要）
tfnet keys pub -in /etc/tfnet/carol.id.json   # identity 公開鍵
tfnet keys pub -in /etc/tfnet/carol.wg.json   # wg 公開鍵
# + 自分の希望 overlay_ip (例 10.99.0.3/32) と endpoint
```

### 提案者 alice の手元（誰でも提案できる）

```sh
cd /var/lib/tfnet/repo
git pull --ff-only

tfnet ledger propose-add \
    -node-id carol \
    -identity-pubkey "<carol-id-pub>" \
    -wg-pubkey       "<carol-wg-pub>" \
    -overlay-ip 10.99.0.3/32 \
    -endpoint 203.0.113.3:51820
# -> ledger/pending/000001-<hash>/entry.json

git add ledger && git commit -m "propose: add carol" && git push
```

ADD は **既存メンバー全員 ∪ {新メンバー}** の署名が必要 → alice / bob / carol の 3 人。

### 各メンバーが署名（順序自由、並列 OK）

```sh
# alice
cd /var/lib/tfnet/repo && git pull --ff-only
tfnet ledger sign -key /etc/tfnet/alice.id.json ledger/pending/000001-*/
git add ledger && git commit -m "alice signs add-carol" && git push

# bob (別ホストで並列に)
cd /var/lib/tfnet/repo && git pull --ff-only
tfnet ledger sign -key /etc/tfnet/bob.id.json ledger/pending/000001-*/
git add ledger && git commit -m "bob signs add-carol" && git push

# carol (まだメンバーじゃないが、新参として参加同意の署名)
git clone git@github.com:our-org/tfnet-ledger.git /var/lib/tfnet/repo
cd /var/lib/tfnet/repo
tfnet ledger sign -key /etc/tfnet/carol.id.json ledger/pending/000001-*/
git add ledger && git commit -m "carol signs add-carol" && git push
```

> **並列 push のときに `git push` が「rejected (non-fast-forward)」になったら**
> `git pull --rebase && git push` でやり直す。署名はファイル単位なので
> 衝突せず素直に rebase が通る。

### 誰か（提案者 alice が普通）が commit

```sh
cd /var/lib/tfnet/repo && git pull --ff-only
tfnet ledger show   ledger/pending/000001-*/   # "all approvals present"
tfnet ledger commit ledger/pending/000001-*/
git add ledger && git commit -m "commit: add carol" && git push
```

### carol が初めて起動

```sh
sudo tfnet sync  -repo /var/lib/tfnet/repo -self carol -hooks-dir /etc/tfnet/hooks.d
sudo tfnet start -self carol -wg-key /etc/tfnet/carol.wg.json -ledger /var/lib/tfnet/repo/ledger
sudo tfnet status -self carol
```

alice / bob 側は次の `tfnet sync` の周期で carol を peer として認識し、フックの
`10-restart-tfnet.sh` が `tfnet start` を再実行 → `wg syncconf` で carol が
ピアに追加される（既存セッションは切れない）。

---

## メンバー削除: REMOVE

退去対象 **以外** の全員の署名が必要。

```sh
# alice の手元 (carol を抜く例)
cd /var/lib/tfnet/repo && git pull --ff-only
tfnet ledger propose-remove -node-id carol
git add ledger && git commit -m "propose: remove carol" && git push

# alice + bob だけが署名 (carol 本人は不要)
tfnet ledger sign -key /etc/tfnet/alice.id.json ledger/pending/<new>/
# bob も同様

tfnet ledger commit ledger/pending/<new>/
git add ledger && git commit -m "commit: remove carol" && git push
```

次の `tfnet sync` で他のホストは carol を `TFNET_REMOVED` として認識し、
restart フックが再起動して wg のピアリストから carol が消える。

> 設計書 §3.2 通り、carol 自身は **REMOVE 操作には署名しない**（退去させられる
> 側の同意は要らない）。carol が物理的にネットワークに残っていても、他全員が
> 「もう繋がない」と決めれば孤立する。

---

## 単一ノードで台帳を持って動かす（開発・検証用）

```sh
tfnet keys gen-identity -node-id alice -out alice.id.json
tfnet keys gen-wg                       -out alice.wg.json
A_ID=$(tfnet keys pub -in alice.id.json | jq -r .identity_pubkey)
A_WG=$(tfnet keys pub -in alice.wg.json | jq -r .wg_pubkey)
cat > spec.json <<EOF
{"subjects":[{"node_id":"alice","identity_pubkey":"$A_ID","wg_pubkey":"$A_WG","overlay_ip":"10.99.0.1/32"}]}
EOF
tfnet ledger init
tfnet ledger genesis -spec spec.json
tfnet ledger sign -key alice.id.json ledger/pending/000000-*/
tfnet ledger commit ledger/pending/000000-*/
sudo tfnet start -self alice -wg-key alice.wg.json
```

---

## tfnet sync — 定期 pull + 変更検知 + フック起動

```
tfnet sync [-repo PATH] [-branch main] [-self ID] [-hooks-dir DIR]
           [-allow-non-ff] [-no-verify] [-json]
```

何をするか:

1. `pre-sync` フック呼び出し
2. `git -C <repo> fetch <remote> <branch>` → `git merge --ff-only`
3. HEAD が動いていなければ `no-change` フックを呼んで終了
4. 新しい台帳を **verify**（ハッシュチェイン + 全署名）。失敗したら `error` フック後 exit 1
5. メンバー集合を pull 前後で diff → `TFNET_ADDED` / `TFNET_REMOVED` を確定
6. `post-update` フックを呼ぶ（実行可能ファイル全て、lexical order）

**非 fast-forward な pull は既定で拒否**（force push を防ぐ）。`-allow-non-ff` で
明示的に許可可能だがコミット履歴の改竄を見逃すので非推奨。

### フックに渡る環境変数

| 変数               | 内容                                                       |
| ------------------ | ---------------------------------------------------------- |
| `TFNET_EVENT`      | `pre-sync` \| `no-change` \| `post-update` \| `error`      |
| `TFNET_REPO`       | git working tree の絶対パス                                 |
| `TFNET_LEDGER_DIR` | 台帳ディレクトリの絶対パス                                  |
| `TFNET_BRANCH`     | 追跡ブランチ                                                |
| `TFNET_REMOTE`     | git remote 名                                               |
| `TFNET_SELF`       | `-self` の値                                                |
| `TFNET_OLD_HEAD`   | pull 前の HEAD SHA                                          |
| `TFNET_NEW_HEAD`   | pull 後の HEAD SHA                                          |
| `TFNET_ADDED`      | 追加された node_id（カンマ区切り）                          |
| `TFNET_REMOVED`    | 削除された node_id                                          |
| `TFNET_GIT_LOG`    | `git log --oneline OLD..NEW`                                |
| `TFNET_ERROR`      | エラー時のみ。失敗内容                                       |

### 既定の hooks-dir 解決順

1. `-hooks-dir <path>` フラグ
2. `$TFNET_HOOKS_DIR`
3. root なら `/etc/tfnet/hooks.d`、非 root なら `~/.config/tfnet/hooks.d`

`-hooks-dir off` または `-hooks-dir -` でフック無効化。

### サンプルフック

`contrib/hooks.d.example/` に 4 つ:

- `10-restart-tfnet.sh.example` — post-update 時に `tfnet start` で reconcile
- `20-notify-desktop.sh.example` — `notify-send` でデスクトップ通知
- `40-slack.sh.example` — Slack webhook 投稿
- `90-log.sh.example` — 簡易テキストログ

`/etc/tfnet/hooks.d/` にコピーして `chmod +x` で有効化。 `.example` 拡張子のままだと
非実行になるので tfnet は無視する（= 安全に放置できる）。

詳細は `contrib/hooks.d.example/README.md` 参照。

### systemd timer で常時 sync

```sh
SYSTEMD=1 ./setup.sh
sudo cp contrib/tfnet-sync.env.example /etc/default/tfnet-sync
sudo vi  /etc/default/tfnet-sync          # TFNET_SYNC_OPTS を編集
sudo systemctl enable --now tfnet-sync.timer
journalctl -u tfnet-sync.service -f
```

既定で **2 分間隔 ± 30 秒ジッタ**。同じ git remote を多数ホストが叩く負荷を均す。

---

## start / stop / status

`tfnet start` がやること（冪等）:

1. WireGuard conf を `/etc/wireguard/<wg-iface>.conf` に書き出して `wg-quick up`
   （既存なら `wg syncconf` でホットリロード）
2. VXLAN: `ip link add tfvx0 type vxlan id 10000 dstport 4789 local <self_overlay> nolearning`
3. Bridge: `ip link add tfbr0 type bridge` → `ip link set tfvx0 master tfbr0`
4. §5.2: `bridge link set dev tfvx0 neigh_suppress on learning off`
5. MTU §6.1: wg=1440, vxlan/bridge=1390
6. FRR conf を書き出して `systemctl reload-or-restart frr`

`tfnet stop`:

1. `vtysh` で `no router bgp <ASN>` / `no bfd`（FRR の他設定を踏まない）
2. vxlan / bridge / wg 各インターフェースを削除

`tfnet status -self <id>`: ピアのハンドシェイク時刻・転送量・BGP/EVPN セッション状態。

### 主要フラグ

| フラグ              | 既定値                       |
| ------------------- | ---------------------------- |
| `-self <id>`        | 必須                          |
| `-wg-key <file>`    | 必須 (start)                 |
| `-ledger <dir>`     | `$TFNET_LEDGER` or `./ledger` |
| `-asn <n>`          | `65010`                      |
| `-wg-iface`         | `tfnet0`                     |
| `-vxlan-iface`      | `tfvx0`                      |
| `-bridge-iface`     | `tfbr0`                      |
| `-vni <n>`          | `10000`                      |
| `-wg-mtu / -overlay-mtu` | `1440 / 1390`           |
| `-dry-run`          | 全 ip/wg/vtysh コマンドを実行せずログ出力のみ |

---

## ログと監査

すべての CLI 実行は `log/slog` で stderr または `-log-file` に構造化ログ。

```sh
tfnet -log-level debug -log-format json -log-file /var/log/tfnet.log ledger commit ...
```

加えて **ホストローカルな** `audit.jsonl` に主要操作が JSONL で蓄積される:

| ホスト種別 | 既定パス                              |
| ---------- | ------------------------------------- |
| root       | `/var/log/tfnet/audit.jsonl`         |
| non-root   | `$XDG_STATE_HOME/tfnet/audit.jsonl`  |

`-audit-file <path>` または `$TFNET_AUDIT_FILE` で上書き、`-audit-file off` で無効化。

audit log は **共有 repo には入れない**（ホストごとに別々で衝突しやすいため）。
ホストの真実をそのホストに残す思想。

### action 一覧

| action                       | いつ                                              |
| ---------------------------- | ------------------------------------------------- |
| `ledger.init`                | `ledger init`                                     |
| `ledger.propose.{genesis,add,remove}` | 各 propose                              |
| `ledger.sign.{inplace,detached}` | `ledger sign`（in-place / `-out`）           |
| `ledger.merge`               | `ledger merge`                                    |
| `ledger.commit`              | `ledger commit`（成功）                           |
| `ledger.commit.rejected`     | 検証失敗                                          |
| `ledger.commit.write_failed` | log への append 失敗                              |
| `ledger.verify.{ok,failed}`  | `ledger verify`                                   |
| `render.{wg,frr}`            | 設定生成                                          |
| `runtime.{start,stop}.{,failed}` | start/stop                                  |
| `sync.{updated,no-change,failed}` | sync 実行結果                                |

---

## ファイル構成

```
リポジトリ（GitHub に push）:
  ledger/
    log.jsonl                       コミット済みエントリ
    pending/<seq>-<hash>/
      entry.json                    提案（提案者が一度書く）
      sigs/<node_id>.json           各員の署名（追加のみ）

ローカル（commit しない）:
  /etc/tfnet/<node>.id.json         Ed25519 identity 秘密鍵
  /etc/tfnet/<node>.wg.json         WireGuard 秘密鍵
  /etc/tfnet/hooks.d/*.sh           ユーザ定義フック
  /etc/wireguard/tfnet0.conf        tfnet start が生成 (再生成可能)
  /etc/frr/frr.conf                 tfnet start が生成 (再生成可能)
  /var/log/tfnet/audit.jsonl        操作監査ログ
```

`.gitignore` には `*.id.json` / `*.wg.json` / `/ledger/` （ローカル開発用）が入っている。
**鍵が間違って repo に紛れ込まない安全策**として明示。

---

## やっていないこと（運用前提）

- **NAT ホールパンチ / リレー**: §4.4・§8 の要確定項目。シグナリングプロトコル未確定。
  当面 A 区分（グローバル IP）と A↔B（B 発呼）のみ繋がる前提。
- **netns 分離**: 設計書 §5.4 は推奨だが、wg-quick の netns サポート都合で
  root netns 前提。`-netns` 拡張の余地は残してある。
- **エンドポイントのローミング配布**: 設計書通り WireGuard 任せ
  （`endpoint` は §3.4 に従い署名対象外）。
