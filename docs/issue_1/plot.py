import matplotlib.pyplot as plt
import os

# Initialize lists to store file sizes and file names
file_sizes = []
file_names = []

# Collect file sizes and names
for i in range(1, 26):
    file_name = f"file_{i}"
    if os.path.exists(file_name):
        file_size = os.path.getsize(file_name) / 1024 / 1024
        file_sizes.append(file_size)
        file_names.append(file_name)

# Create a bar graph
plt.bar(file_names, file_sizes, color="blue")
plt.xlabel("File Names")
plt.ylabel("File Size (MiB)")
plt.title("Random File Sizes")
plt.xticks(rotation=90)  # Rotate x-axis labels for better readability
plt.tight_layout()

# Show the graph
plt.savefig("file_sizes.png", format="png")
