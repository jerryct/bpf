#/usr/bin/env sh

set -eu

script_root="$(cd "$(dirname "$0")" && pwd)"

exe=`ls -l /proc/$1/exe | awk '{ print $(NF) }'`
offset=`objdump -tT --demangle /proc/$1/exe | grep "$2" | awk -e '{ print "0x"$1 }'`

echo > /sys/kernel/debug/tracing/uprobe_events
echo "p:stackcount $exe:$offset" > /sys/kernel/debug/tracing/uprobe_events
cat /sys/kernel/debug/tracing/uprobe_events

address=`awk -e '$6 !~ /\[.*\]/ && /r-xp/ { n = split($1,a,"-"); print $6,a[1],a[2] }' /proc/$1/maps`

exec "$script_root/stackcount" $1 $address
