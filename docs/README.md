
# Bitrot

Bitrot is a command-line program that compares file checksums vs. known file checksums. It's a lot like [hashdeep](https://github.com/jessek/hashdeep), but it's written 100% in Rust and probably isn't as feature-complete.

## Why does this exist?
###### Aka, why not just use Hashdeep?

There's a few reasons:
1. [Hashdeep](https://github.com/jessek/hashdeep) appears to not be making new releases since 2014. Well... maybe its feature-complete and considered done? If that were true, why are there 127 issues that at [least](https://github.com/jessek/hashdeep/issues/413) [a](https://github.com/jessek/hashdeep/issues/404) [few](https://github.com/jessek/hashdeep/issues/400) seem valid and un-replied to in *years*.)
2. Hashdeep appears to be written in C/C++ and I don't know those languages, and I'm not interested in learning those if I want to hack in my own features. 
3. I wanted to learn Rust. Coming from a C# background, I like Rust's sytax. It seems like a fast, modern language. And a bonus I discovered after starting to use it - it has a great approach to concurrency.