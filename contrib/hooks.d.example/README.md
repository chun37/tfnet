# tfnet hooks

`tfnet sync` runs every executable file in `<hooks-dir>` (lexical order) on
every invocation, with a tinc-up-style environment.

## Install

Each example file ends in `.example` and is **not** executable, so it's
ignored by tfnet. To enable:

```sh
sudo install -m 0755 /usr/share/tfnet/hooks.d.example/10-restart-tfnet.sh.example \
                     /etc/tfnet/hooks.d/10-restart-tfnet.sh
```

Or copy + edit + `chmod +x`. Drop your own scripts here too.

## Environment variables every hook receives

| Variable           | Always set | Description                                                  |
| ------------------ | :--------: | ------------------------------------------------------------ |
| `TFNET_EVENT`      | yes        | `pre-sync` \| `no-change` \| `post-update` \| `error`        |
| `TFNET_REPO`       | yes        | Absolute path to the git working tree                        |
| `TFNET_LEDGER_DIR` | yes        | Absolute path to the ledger directory inside the repo       |
| `TFNET_BRANCH`     | yes        | Branch being tracked (default `main`)                        |
| `TFNET_REMOTE`     | yes        | Git remote name (default `origin`)                           |
| `TFNET_SELF`       | yes        | self node_id (empty if `-self` not passed)                   |
| `TFNET_OLD_HEAD`   | yes        | Commit SHA before pull (empty on hard error)                 |
| `TFNET_NEW_HEAD`   | yes        | Commit SHA after pull                                        |
| `TFNET_ADDED`      | yes        | Comma-separated node_ids that became members                 |
| `TFNET_REMOVED`    | yes        | Comma-separated node_ids that left                           |
| `TFNET_GIT_LOG`    | yes        | `git log --oneline OLD..NEW` (multi-line)                    |
| `TFNET_ERROR`      | error only | Failure message                                              |

## Recipe: only act on real change

```sh
case "${TFNET_EVENT:-}" in
  post-update) ;;
  *) exit 0 ;;
esac
```

## Recipe: only act when peer set changed

```sh
if [ -z "${TFNET_ADDED:-}" ] && [ -z "${TFNET_REMOVED:-}" ]; then
    exit 0
fi
```

## Order

Files are run in `LC_ALL=C` sort order, so number-prefix them: `10-restart`,
`20-notify`, `90-log`. A hook that fails (non-zero exit) is logged but
**does not stop subsequent hooks** -- a broken Slack notification should
not prevent the local restart hook from running.
