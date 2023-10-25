
# Program needs a mode to create checksums

## Problem Statement

For hasdeep compatability, bitrot needs to be able to generate hashdeep-compatible files for running hashdeep-like audits. 

## Performance compare

Testing on 287 files, 30GiB of data. It worked for this small test, it's compatible, and bitrot was faster in real time by just a smidge!

```
# /usr/bin/time -p /root/bitrot -d /jf_data/ -c /jf_par2/ -m cr -b 1000 -r ".+" -t 8  -e ~/bitrot_output.txt -p
real 14.54
user 62.00
sys 15.93
```
*Install autoconf automake gcc g++ to build:*
```
git clone https://github.com/jessek/hashdeep.git
cd hashdeep
./configure --build=none
# /usr/bin/time -p ./src/hashdeep -c md5 -r ~/tmp > hashdeep.knowns
real 14.85
user 78.46
sys 4.81
```

```
root@ded786e6944a ~ # hashdeep -r -a -k hashdeep.knowns /jf_data 
hashdeep: Audit passed
root@ded786e6944a ~ # hashdeep -r -a -k bitrot_output.txt /jf_data
hashdeep: Audit passed
```
