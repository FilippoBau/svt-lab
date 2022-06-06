# fill the buffer with 128 chars
payload='AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
# put the right int to bypass the condition, in little endian
payload="$payload*\x00\x00\x00"

echo -e $payload
echo -ne $payload | ./crackme1
