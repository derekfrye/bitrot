import hashlib
import os
import random

random.seed(0)

ll = list(range(2000))
lp = random.choices(ll, k = 100)

# Create 25 big files, random size under 2GiB
for i in range(1, 26):
    size = lp[i] * 1024 * 1024

    # Create a file with somewhat random data
    with open(f"file_{i}", "wb") as file:
        random_data = os.urandom(size)
        file.write(random_data)

    # Compute checksum 
    md5_hash = hashlib.md5(random_data).hexdigest()

    # Write the checksum 
    with open(f"file_{i}.md5.txt", "w") as md5_file:
        md5_file.write(md5_hash)

    print(
        f"Created file_{i} with size {size/(1024*1024):.2f} MiB and MD5 checksum {md5_hash}"
    )
