# # Specify the path to your .txt file
# file_path = '/home/rahul.m/Downloads/cryptography-io-en-latest.txt'
# count = 0
# # Open and read the file
# with open(file_path, 'r') as file:
#     lines = file.readlines()

# # Filter lines that start with "class cryptography"
# filtered_lines = [line for line in lines if line.startswith('class cryptography')]

# # Print the filtered lines
# for line in filtered_lines:
#     print(line.strip())
#     count+=1

# print(count)


# Specify the path to your .txt file
file_path = '/home/rahul.m/Downloads/cryptography-io-en-latest.txt'
count = 0
# Open and read the file
with open(file_path, 'r') as file:
    lines = file.readlines()

# Filter lines that start with "class cryptography"
filtered_lines = [line for line in lines if line.startswith('class cryptography')]

# Extract text before '('
for line in filtered_lines:
    # Find the index of the first '('
    index = line.find('(')
    if index != -1:
        # Extract and print text before '('
        print(line[:index].strip())
    else:
        # Print the whole line if no '(' is found
        print(line.strip())
    count+=1

print(count)
