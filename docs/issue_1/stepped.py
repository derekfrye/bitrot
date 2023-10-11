#!/usr/bin/env python3

import hashlib
import os
# import random

# random.seed(0)

first_file = 2 * 1024 * 1024 * 1024
step_size = first_file

# Create 25 big files
for i in range(1, 26):
    # Generate a random size between 100MiB and 2GiB in bytes
    size = step_size

    # Create a file with somewhat random data
    with open(f"file_{i}", "wb") as file:
        random_data = os.urandom(size)
        file.write(random_data)

    # Compute checksum
    md5_hash = hashlib.md5(random_data).hexdigest()

    # Write the checksum
    with open(f"file_{i}.md5.txt", "w") as md5_file:
        md5_file.write(md5_hash)

    if i % 2 == 0:
        step_size //= 2
    else:
        step_size -= 1

    print(
        f"Created file_{i} with size {size/(1024*1024):.2f} MiB and MD5 checksum {md5_hash}"
    )
