# GUI Phase 3 — Moving the React Interface from Mock to Real Data

> Progress record. Phase 1 (interface port) and Phase 2 (DataSource
> extraction) are complete and merged to master.

## Completed

| | commit | Contents |
|---|---|---|
| Phase 1 | `a816609` | 6 components + three `lib/` files ported byte-for-byte from TelcoShark-Sandbox, served at `/app/<sid>` |
| Phase 2 | `5885aca` | `DataSource` interface, `mockSource` / `apiSource`, `App.tsx` owning loading and failure states |
| Phase 3 prerequisite | `5434a87` | `/index` gains tcp/udp/sctp ports (`RawPacket` needs `IP:port`) |

## Current `/index` → `RawPacket` mapping

| `RawPacket` field | Source | Status |
|---|---|---|
| `frameNumber` | `n` | ✅ |
| `timestamp` / `epochMicroseconds` | `epoch` | ✅ |
| `srcIp` / `dstIp` | `src` / `dst` | ✅ |
| `srcPort` / `dstPort` | `sport` / `dport` | ✅ (`5434a87`) |
| `length` / `info` | `len` / `info` | ✅ |
| `protocol` | `proto` | ⚠ typed as an 8-value union; actual values are arbitrary strings (`NGAP/NAS-5GS`) |
| `domain` | derived from `stack` | ⚠ mapping still to be written |
| `correlatedSupi` / `status` | reverse lookup from `/flows` | ❌ session rows do not yet carry frame lists |
| `decodeTree` | `/decode?frame=N` | ⚠ lazy-loaded; `DataSource` needs a second method |
| `hexDump` | — | ❌ **the backend has no hex output at all** |

## The two large pieces not yet started

- **Structured call-flow API** — currently returns an SVG string with
  y-coordinates fixed in Python, which cannot support the dynamic lane
  add/remove and Domain switching the TelcoLadder interface requires.
- **Scale** — the GUI treats all packets as one in-memory array with
  client-side filtering. Real pcaps run to hundreds of thousands of packets
  and would lock the page. Requires windowing, and moving
  `computeDiscoveredSessions`' full-population aggregation to the server
  (`flows_json` already does this, with tests).

## Divergence record

`web/PORTED.json`'s `diverged` section records which ported files have
deliberately departed from their source. **Diverged files remain
hash-pinned** — intentional divergence is not a licence for future drift.
