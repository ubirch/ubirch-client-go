#! /bin/bash
[ "$1" = "" ] && echo "missing a number as argument" && exit 1
# replace owner with your UUID and token with the password
owner=0000000-0000-0000-0000-0000000000000
token=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
# we generate a random uuid for the message id
uuid=$(uuidgen)
# the message looks very simple
msg='{"id":"'$uuid'","result":0,"value":'$1'}'
echo "message sent: $msg"
echo -n "calculated hash: "
echo -n "$msg" | sha256sum -b | awk '{print $1;}' |xxd -r -ps | base64
echo -n "$msg" | sha256sum -b | awk '{print $1;}' |xxd -r -ps > __msg.bin
curl -v \
    --url "http://localhost:8080/$owner/hash" \
    --header "content-type: application/octet-stream" \
    --header "x-auth-token: $token" \
    --data-binary @__msg.bin
