#!/usr/bin/env bash
# 產生一個場景的擷取檔與核網日誌。
#
# 用法：capture-scenario.sh <場景名> [KEY=VALUE ...]
#   KEY=VALUE 會覆寫 docker_open5gs 的 .env（例如 UE1_KI=...），
#   跑完自動還原，所以連續跑多個場景不會互相污染。
#
# 為什麼要重建 UE 容器而不是 restart：compose 的 env_file 只在 up 時讀，
# restart 不會重新代入新的 .env 值。
#
# macOS 注意：Docker 跑在 VM 裡，host 看不到 bridge 介面，
# 所以 tcpdump 必須在容器的網路命名空間內執行。

set -euo pipefail

SCENARIO="${1:?用法: capture-scenario.sh <場景名> [KEY=VALUE ...]}"
shift

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# docker_open5gs 是外部 repo，clone 到 local/（已 gitignore）：
#   git clone --depth 1 https://github.com/herlesupreeth/docker_open5gs.git local/docker_open5gs
STACK="$REPO/local/docker_open5gs"
OUT="$REPO/local/scenarios/$SCENARIO"
ENV="$STACK/.env"

mkdir -p "$OUT/logs"
cp "$ENV" "$ENV.scenario-backup"
restore() { mv -f "$ENV.scenario-backup" "$ENV" 2>/dev/null || true; }
trap restore EXIT

for kv in "$@"; do
  key="${kv%%=*}"
  printf '  覆寫 %s\n' "$kv"
  # BSD sed 與 GNU sed 都吃這個寫法
  sed -i.tmp "s|^${key}=.*|${kv}|" "$ENV" && rm -f "$ENV.tmp"
done

cd "$STACK"

# 抓包要先開，否則錯過 UE 的第一則訊息
docker exec amf sh -c 'rm -f /tmp/scenario.pcap' 2>/dev/null || true
docker exec -d amf tcpdump -i any -w /tmp/scenario.pcap -U 'sctp'
sleep 2

echo "  重建 UE 容器…"
DOCKER_DEFAULT_PLATFORM=linux/amd64 docker compose -f nr-ue.yaml up -d --force-recreate >/dev/null 2>&1
sleep 12

docker exec amf pkill -INT tcpdump 2>/dev/null || true
sleep 2

docker cp amf:/tmp/scenario.pcap "$OUT/capture.pcap" >/dev/null
for c in amf ausf udm; do
  docker logs --since 30s "$c" 2>&1 | sed 's/\x1b\[[0-9;]*m//g' > "$OUT/logs/$c.log"
done
docker logs --tail 40 nr_ue 2>&1 | sed 's/\x1b\[[0-9;]*m//g' > "$OUT/logs/ue.log"

echo "  → $OUT"
