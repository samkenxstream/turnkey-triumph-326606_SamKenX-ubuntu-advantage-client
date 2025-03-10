#!/usr/bin/bash
series=$1

set -x

build_out=$(./tools/build.sh $series)
hash=$(echo $build_out | jq -r .state_hash)
deb=$(echo $build_out | jq -r .debs[] | grep tools)
name=ua-$series-$hash

multipass delete $name --purge
multipass launch $series --name $name
sleep 30
# Snaps won't access /tmp
cp $deb ~/ua.deb
multipass transfer ~/ua.deb $name:/tmp/ua.deb
rm -f ~/ua.deb

if [ -n "$SHELL_BEFORE" ]; then
    set +x
    echo
    echo
    echo "New version of pro has not been installed yet."
    echo "After you exit the shell we'll upgrade pro and bring you right back."
    echo
    set -x
    multipass exec $name bash
fi

multipass exec $name -- sudo dpkg -i /tmp/ua.deb
multipass shell $name
