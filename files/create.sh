# 1 KB text file command
dd if=/dev/urandom bs=1024 count=5 | tr -cd '[:alnum:]' | head -c 1024 > kb_1.txt

# 10kb text file
dd if=/dev/urandom bs=1024 count=50 | tr -cd '[:alnum:]' | head -c 10240 > kb_10.txt

# 1 MB binary file
dd if=/dev/urandom of=mb_1.bin bs=1M count=1

# 2 MB binary file 
dd if=/dev/urandom of=mb_2.bin bs=1M count=2

# 3 MB text file
dd if=/dev/urandom of=mb_3.bin bs=1M count=3

