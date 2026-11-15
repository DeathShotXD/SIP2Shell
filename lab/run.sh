#!/usr/bin/env bash
# Boot a real FreeSWITCH for SIP2Shell testing.
#
#   ./run.sh                 # vulnerable 1.10.12
#   ./run.sh patched         # 1.11.3 (the enable-chat-api-proto gate -> 403)
#   ./run.sh vuln 1.10.7     # any safarov/freeswitch tag
#
# Uses host networking so the read-back MESSAGE returns to the operator.
set -euo pipefail

WHICH="${1:-vuln}"
TAG="${2:-1.10.12}"
case "$WHICH" in
  patched|fixed) TAG="${2:-1.11.3}" ;;
esac
IMAGE="safarov/freeswitch:${TAG}"
NAME="sip2shell-fsw"

docker rm -f "$NAME" >/dev/null 2>&1 || true

# stock vanilla config, a known SIP password, and MESSAGE auth off
BOOTSTRAP='
set -e
[ -f /etc/freeswitch/freeswitch.xml ] || cp -a /usr/share/freeswitch/conf/vanilla/. /etc/freeswitch/
sed -i "s/default_password=.*/default_password=1234\"/" /etc/freeswitch/vars.xml 2>/dev/null || true
for p in internal external; do
  f=/etc/freeswitch/sip_profiles/$p.xml
  [ -f "$f" ] || continue
  grep -q auth-messages "$f" || sed -i "s#<settings>#<settings>\n    <param name=\"auth-messages\" value=\"false\"/>#" "$f"
done
exec /usr/bin/freeswitch -nc -nf -nonat
'

docker run -d --name "$NAME" --network host \
  --entrypoint /bin/sh "$IMAGE" -c "$BOOTSTRAP" >/dev/null

echo "[*] $IMAGE up ($WHICH). waiting for SIP 5060..."
IP="$(hostname -I 2>/dev/null | awk '{print $1}')"
for _ in $(seq 1 20); do
  sleep 1
  if (echo > /dev/udp/127.0.0.1/5060) 2>/dev/null; then break; fi
done
sleep 3
docker logs --tail 3 "$NAME" 2>&1 || true
echo
echo "[+] target: ${IP:-127.0.0.1}:5060   (if 403 -> patched, if 202 -> vulnerable)"
echo "    python3 ../sip2shell.py probe -t ${IP:-127.0.0.1}"
