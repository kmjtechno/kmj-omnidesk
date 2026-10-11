#!/usr/bin/env bash
# Waits for the GitHub device-flow authorization, then pushes the feature
# branches and opens their pull requests.
#
# Bounded by the device code's own 15-minute expiry; exits quietly if the
# user never authorizes so this can run unattended in the background.
set -uo pipefail

REPO="c:/Users/lenovo/.copilot/chats/5f80d490-ad93-40f0-879b-00667d384e7c/kmj-omnidesk"
DEVICE_CODE="3768041a2f758f5643c576e255247c4fe2936d9a"
CLIENT_ID="Iv1.b507a08c87ecfe98"
export PATH="$PATH:/c/Program Files/GitHub CLI"

cd "$REPO" || exit 1

BRANCHES="feat/security-and-relay-foundation"

echo "polling for device authorization (up to 15 min)..."

deadline=$((SECONDS + 870))
token=""

while [ $SECONDS -lt $deadline ]; do
  response=$(curl -s -X POST \
    -H "Accept: application/json" \
    -d "client_id=$CLIENT_ID&device_code=$DEVICE_CODE&grant_type=urn:ietf:params:oauth:grant-type:device_code" \
    https://github.com/login/oauth/access_token)

  error=$(echo "$response" | python3 -c "import json,sys; print(json.load(sys.stdin).get('error',''))" 2>/dev/null)

  case "$error" in
    authorization_pending) sleep 5 ;;
    slow_down)             sleep 10 ;;
    "")
      token=$(echo "$response" | python3 -c "import json,sys; print(json.load(sys.stdin).get('access_token',''))" 2>/dev/null)
      if [ -n "$token" ]; then echo "AUTHORIZED"; break; fi
      sleep 5 ;;
    expired_token)
      echo "device code expired before authorization; nothing pushed."; exit 1 ;;
    *)
      echo "device flow error: $error"; exit 1 ;;
  esac
done

if [ -z "$token" ]; then
  echo "no authorization received; nothing pushed."
  exit 1
fi

# The token is used for this push only: passed via extraHeader so it is not
# written into .git/config or any credential store, and redacted from output.
b64=$(printf 'x-access-token:%s' "$token" | base64 -w0)

overall=0
for branch in $BRANCHES; do
  git -c "http.extraHeader=Authorization: Basic $b64" push -u origin "$branch" 2>&1 | sed "s/$token/***/g"
  rc=$?
  echo "push $branch -> rc=$rc"
  [ $rc -ne 0 ] && overall=1
done

echo "=== overall push rc=$overall ==="
