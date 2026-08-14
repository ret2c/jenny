# Optional research tools

These tools are intentionally installed on demand. They are not required for
JENNY setup, mailbox operation, package review, or the dashboard. Install one
only when the active target has a concrete lane that needs it, and record the
exact version in target-local evidence.

| Tool | Pinned source used previously | Intended use |
|---|---|---|
| WTF | `https://github.com/0vercl0k/wtf.git` at `c34687703fdf4c181a7e5f1452722dec0e8f93fa` | Snapshot-based Windows fuzzing |
| honggfuzz | `https://github.com/google/honggfuzz.git` at `48790f7b18f30ba4a95272ea290b720662ed56c9` | Native coverage-guided fuzzing |
| OSS-Fuzz | `https://github.com/google/oss-fuzz.git` at `c96c4482b76ed098d21f2ed4d0478dbfb6bd6ec9` | Upstream-compatible fuzz integration |
| LibAFL | `https://github.com/AFLplusplus/LibAFL.git` at `22162de71f9a53c357c1651193a822a63e53b089` | Custom fuzzing pipelines |
| boofuzz | `https://github.com/jtpereyda/boofuzz.git` at `295f329624a6ba60723bc9881e2a683431c59395` | Stateful network protocol fuzzing |
| WinAFL | `https://github.com/googleprojectzero/winafl.git` at `fd85f38548b14352f4b70ad414f364ea6dc1a769` | Windows binary fuzzing |
| TinyInst | `https://github.com/googleprojectzero/TinyInst.git` at `4653c0eaa2a1d1a651b46605b02064f5897e5a56` | Windows binary instrumentation |
| Jackalope | `https://github.com/googleprojectzero/Jackalope.git` at `c4a5b46b159fc6af030fddab60b78c8fdba9a365` | Optional TinyInst-based fuzzing; endpoint protection may block it |
| BNSQL | `https://github.com/0xeb/bnsql.git` at `234cf1815615fc628f12e1647a9304f25799b2ee` | Binary Ninja export/query experiments |
| r2sql | `https://github.com/0xeb/r2sql.git` at `ae47d685f644a9d869c5f983fe4295b508fa3d1c` | radare2 export/query experiments |
| libxsql | `https://github.com/0xeb/libxsql.git` at `59410e4e81ab45a7123d6294e7c1b877ce4f381b` | Shared SQL-export support for the preceding tools |

Rehydrate a pinned Git tool with:

```text
git clone <source-url> <target-directory>
git -C <target-directory> checkout --detach <commit>
git -C <target-directory> rev-parse HEAD
```

Do not weaken endpoint protection merely to satisfy an optional tool. If a
tool cannot pass its native prerequisites or conflicts with host policy, leave
it absent and use a supported target-specific harness.
