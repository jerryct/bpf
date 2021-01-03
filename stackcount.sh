#/usr/bin/env sh

set -eu

script_root="$(cd "$(dirname "$0")" && pwd)"

if [ $# -ne 2 ]
then
  echo "Usage: stackcount.sh pid function_name"
  exit 1
fi

exe=`ls -l /proc/$1/exe | awk '{ print $(NF) }'`
symbol=`objdump -tT --demangle /proc/$1/exe | egrep 'F[ ]+\.text' | grep "$2"`

if [ -z "$symbol" ]
then
  echo "No symbol found"
  exit 1
else
  echo "$symbol"
fi

offset=`echo $symbol | awk -e 'NR==1 { print "0x"$1 }'`
echo > /sys/kernel/debug/tracing/uprobe_events
echo "p:stackcount $exe:$offset" > /sys/kernel/debug/tracing/uprobe_events
cat /sys/kernel/debug/tracing/uprobe_events

address=`awk -e '$6 !~ /\[.*\]/ && /r-xp/ { n = split($1,a,"-"); print $6,a[1],a[2] }' /proc/$1/maps`

exec "$script_root/stackcount" $1 $address
