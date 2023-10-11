
# Threads ask for next unit of work

## Proble Statement

Rather than assigning work by thread up-front (which is current in main as of [9e4ecb2](https://github.com/derekfrye/bitrot/commit/9e4ecb2ca201ec5a459e4600d802a7c522d60ed4)), we want each worker thread to ask the main thread for the next unit of work. 

Why? Well, in some corner cases, I think that asking for the next unit of work could be more performant than pre-assigning files to each thread up-front. 

Here's one such corner case:
1. Suppose you many files to checksum. To keep the example simple, let's use just two worker threads. 
2. Suppose filesizes are this *admittedly* wacky size distribution: First file is $n$ bytes, next file is $n/2$ bytes, next file is $n/2-1$ bytes, next file is $(n/2-1)/2$ bytes, etc.
3. Then, in [today's implementation](https://github.com/derekfrye/bitrot/commit/9e4ecb2ca201ec5a459e4600d802a7c522d60ed4) which pre-allocates all files to the worker threads one at a time in filesize order:[^1]
    1. Thread 1 files to checksum: $n$ bytes, $n/2-1$ bytes, $(n/2-1)/2-1$ bytes, etc.
    2. Thread 2 files to checksum: $n/2$ bytes, $(n/2-1)/2$ bytes, $((n/2-1)/2-1)/2$ bytes, etc.
4. Basically, Thread 2 has half the bytes to process as Thread 1. So all other things being equal, Thread 2 will be done in half the overall program's runtime, and it'll sit there doing nothing while Thread 1 has a long queue of work. So in this corner case, Thread 2 can't help Thread 1 and so the overall program runtime is longer than it should be. 

Maybe I'm totally crazy. Let's test this. (FYI, this was previously coded since I wanted to learn about bi-directional channels in Rust.) But now seems like a great chance to test this! 


[^1]: In [today's implmentation](https://github.com/derekfrye/bitrot/commit/9e4ecb2ca201ec5a459e4600d802a7c522d60ed4), main.rs (line 39) reads all the files matching our regex using `read_dir`, then function `assign_work()` sorts the files by `PathBuf.metadata().len()`. Finally, line 74 of main.rs cycles through the filesize-sorted `PathBuf` vector, handing each `PathBuf`` off to a new thread, one-by-one, in the sorted order.

