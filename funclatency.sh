#/usr/bin/env sh
#
# Time function and print statistics
#
# Nested or recursive functions are not supported and
# timestamps will be overwritten, creating dubious output.

set -eu

script_root="$(cd "$(dirname "$0")" && pwd)"

if [ $# -ne 2 ]
then
  echo "Usage: funclatency.sh pid symbol_address"
  exit 1
fi

exe=`ls -l /proc/$1/exe | awk '{ print $(NF) }'`
address=`cat /proc/$1/maps | grep "$exe" | grep r-xp | awk 'NR==1 { n = split($1,a,"-"); print a[1] }'`
offset=`printf "0x%X\n" $((0x$2 - 0x$address))`

echo "p:funclatency_entry $exe:$offset" > /sys/kernel/debug/tracing/uprobe_events
echo "r:funclatency_return $exe:$offset" >> /sys/kernel/debug/tracing/uprobe_events
cat /sys/kernel/debug/tracing/uprobe_events

exec "$script_root/funclatency"
