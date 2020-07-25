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
offset=`objdump -tT --demangle /proc/$1/exe | grep "$2" | awk -e '{ print "0x"$1 }'`

echo "p:funclatency_entry $exe:$offset" > /sys/kernel/debug/tracing/uprobe_events
echo "r:funclatency_return $exe:$offset" >> /sys/kernel/debug/tracing/uprobe_events
cat /sys/kernel/debug/tracing/uprobe_events

exec "$script_root/funclatency"
