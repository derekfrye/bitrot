
# Program needs a mode to create checksums

## TLDR



## Problem Statement



## Performance compare

Testing on 72 files, 30GiB of data.

```
# touch errors_bitrot.txt && rm errors_bitrot.txt && /usr/bin/time -p /root/bitrot -d /jf_data/ -c /jf_par2/ -m ck -b 512 -r "<regex>" -t 4 -p -e ~/errors_bitrot.txt -a
real 32.53
user 51.07
sys 12.46

/usr/bin/time -p hashdeep -c md5 -r /jf_data > /root/hashdeep.knowns
real 14.85
user 78.46
sys 4.81
```
