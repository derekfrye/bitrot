
# Threads "ask" for next unit of work, vs. pre-assigning files

## TLDR

This will merge as an *optional* scheduler since it appears to be *slower*!

## Problem Statement

Rather than assigning work by thread up-front (which is current in main as of [9e4ecb2](https://github.com/derekfrye/bitrot/commit/9e4ecb2ca201ec5a459e4600d802a7c522d60ed4)), we want each worker thread to ask the main thread for the next unit of work. 

Why? Well, in some corner cases, I think that asking for the next unit of work could shorten overall runtime vs. pre-assigning files to each thread up-front. 

Here's one such corner case:
1. To keep the example simple, let's use just two worker threads. 
2. Suppose filesizes follow this *admittedly* wacky size distribution: First file is $n$ bytes, next file is $n/2$ bytes, next file is $n/2-1$ bytes, next file is $(n/2-1)/2$ bytes, etc.
3. Then, in [today's implementation](https://github.com/derekfrye/bitrot/commit/9e4ecb2ca201ec5a459e4600d802a7c522d60ed4) we pre-allocate all files to the worker threads one at a time, in filesize order:[^1]
    1. Thread 1 files to checksum: $n$ bytes, $n/2-1$ bytes, $(n/2-1)/2-1$ bytes, etc.
    2. Thread 2 files to checksum: $n/2$ bytes, $(n/2-1)/2$ bytes, $((n/2-1)/2-1)/2$ bytes, etc.
4. Basically, Thread 2 has half the bytes to process as Thread 1. So all other things being equal, Thread 2 will be done in half the overall program's runtime, and it'll sit there doing nothing while Thread 1 has a long queue of work. So in this corner case, Thread 2 can't help Thread 1 and the overall program runtime is needlessly long. 

Let's test this. (FYI, this has been coded in branch issue_1 since I wanted to learn about bi-directional channels in Rust anyway.) And now it seems like a great chance to test this!

Let's use [stepped.py](stepped.py) to create 25 big files that follow this size distribution.

```
% python3 stepped.py
Created file_1 with size 2048.00 MiB and MD5 checksum de4b0e86d345e1ec35af74a2ca18cddb
Created file_2 with size 2048.00 MiB and MD5 checksum ce1de755632a8a1faded20687322c6fd
Created file_3 with size 1024.00 MiB and MD5 checksum 9b1842701dc30ea1386fd933f762cc0e
Created file_4 with size 1024.00 MiB and MD5 checksum c59af8f78f44b50d711a6be96fea41ba
Created file_5 with size 512.00 MiB and MD5 checksum 3208ef55b840c0b6bc6031c5852f0730
Created file_6 with size 512.00 MiB and MD5 checksum 7387771b5fd49c4781bbf356eebeeaf2
Created file_7 with size 256.00 MiB and MD5 checksum 147b84e7c79052524f7048daffcb1329
Created file_8 with size 256.00 MiB and MD5 checksum ebe09af5506f9193bd6626dcb7917c08
Created file_9 with size 128.00 MiB and MD5 checksum c09162b5b94b7fc4913e2863495d4c61
Created file_10 with size 128.00 MiB and MD5 checksum 6d3edaa876496cfc380f449c551672e1
Created file_11 with size 64.00 MiB and MD5 checksum b28dce3ae330d51f137e397bcc66eb58
Created file_12 with size 64.00 MiB and MD5 checksum 1ad29986632f71155593015c940fce23
Created file_13 with size 32.00 MiB and MD5 checksum ab5bfe25084c15a9eafb2afb1c32e5e3
Created file_14 with size 32.00 MiB and MD5 checksum 8223f094f61b1ae0e9fcd0573b76df58
Created file_15 with size 16.00 MiB and MD5 checksum 3d232547b3cb72e50d75aed1363ff295
Created file_16 with size 16.00 MiB and MD5 checksum 2df7906b5218e8af68961e9b4a6c90a5
Created file_17 with size 8.00 MiB and MD5 checksum 15264933ac9bc8cfe76bd1ac86bddbd6
Created file_18 with size 8.00 MiB and MD5 checksum d15c3fd801a7b0da898842cbd2775e0e
Created file_19 with size 4.00 MiB and MD5 checksum 335118484b67a53dfb61a2731276ac7d
Created file_20 with size 4.00 MiB and MD5 checksum 5fd93b26ca602a5f047cbafafb71264f
Created file_21 with size 2.00 MiB and MD5 checksum a48bcd520c0322caf320fba03687cc73
Created file_22 with size 2.00 MiB and MD5 checksum 18aa1b868b4518b0fd0a4e0f3dc49176
Created file_23 with size 1.00 MiB and MD5 checksum 58d3189dce6a86055d22745598772768
Created file_24 with size 1.00 MiB and MD5 checksum 5439049f2c0cc3070ffef46486921175
Created file_25 with size 0.50 MiB and MD5 checksum 75ae7567a61b8ee77e0c5febda491b1d
```

Let's test runtime now with our current issue_1 branch. Let's use 4 threads.
```
% /usr/bin/time -p ~/src/bitrot/target/release/bitrot -d ~/src/bitrot/docs/issue_1/tmp/ -c ~/src/bitrot/docs/issue_1/tmp2/ -m ck -b 512 -r "file_" -t 4  -e output.txt  
Using data path /home/m1n2/src/bitrot/docs/issue_1/tmp/ and checksums path /home/m1n2/src/bitrot/docs/issue_1/tmp2/
real 15.62
user 14.35
sys 3.39
```

Now let's switch back to the main branch and test timing. 
```
% /usr/bin/time -p ~/src/bitrot_master/target/release/bitrot -d ~/src/bitrot/docs/issue_1/tmp/ -c ~/src/bitrot/docs/issue_1/tmp2/ -m ck -b 512 -r "file_" -t 4  -e output.txt   
Using data path /home/m1n2/src/bitrot/docs/issue_1/tmp/ and checksums path /home/m1n2/src/bitrot/docs/issue_1/tmp2/
real 6.35
user 6.43
sys 8.55
```

Whoa! Turns out that the new scheduler is *slower*. Maybe the overhead of communicating back and forth to the main thread, and/or how I wrote it, is just inefficient! 

If I do merge this branch back in, it should be as an optional feature, clearly.

## Post merge performance update

Testing on 71 files, 29GiB of data. Alternate scheduler definitely *doesn't* win!

```
# touch errors_bitrot.txt && rm errors_bitrot.txt && /usr/bin/time -p /root/bitrot -d /jf_data/ -c /jf_par2/ -m ck -b 512 -r "<regex>" -t 4 -p -e ~/errors_bitrot.txt -a
real 32.53
user 51.07
sys 12.46

touch errors_bitrot.txt && rm errors_bitrot.txt && /usr/bin/time -p /root/bitrot -d /jf_data/ -c /jf_par2/ -m ck -b 512 -r "<regex>" -t 4 -p -e ~/errors_bitrot.txt  
real 19.09
user 50.49
sys 7.13
```

[^1]: In [today's implmentation](https://github.com/derekfrye/bitrot/commit/9e4ecb2ca201ec5a459e4600d802a7c522d60ed4), main.rs (line 39) reads all the files matching our regex using `read_dir`, then function `assign_work()` sorts the files by `PathBuf.metadata().len()`. Finally, line 74 of main.rs cycles through the filesize-sorted `PathBuf` vector, handing each `PathBuf`` off to a new thread, one-by-one, in the sorted order.

