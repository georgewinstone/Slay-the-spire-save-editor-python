from __future__ import print_function, unicode_literals
from os import urandom
import glob
import base64

savefile = glob.glob('*_old*')[0]


with open (savefile, "r") as myfile:
    encoded=myfile.readlines()[0]
    



#save the decdes from base 64 file
your_data = base64.b64decode(encoded)
#print(your_data,  file=open('test.txt', 'w'))



def genkey(length: int) -> bytes:
    """Generate key."""
    return urandom(length)
    

def xor_strings(s, t) -> bytes:
    """xor two strings together."""
    if isinstance(s, str):
        # Text strings contain single characters
        return b"".join(chr(ord(a) ^ ord(b)) for a, b in zip(s, t))
    else:
        # Python 3 bytes objects contain integer values in the range 0-255
        return bytes([a ^ b for a, b in zip(s, t)])
        
# 
# key = genkey(10)
# key = 'aaaaa'.encode('utf-8')
# print('key:',key,'\n')
# 
# print('decrypted:', xor_strings(your_data, key))
# 



##################


def hamming_distance(bytes1, bytes2):
  # The strings must be equal length or this will fail.
  assert len(bytes1) == len(bytes2)

  distance = 0
  for zipped_bytes in zip(bytes1, bytes2):
    # XOR a bit from bytes1 with the corresponding bit in bytes2
    x = zipped_bytes[0] ^ zipped_bytes[1]

    set_bits = 0
    while (x > 0):
      # Check if the right most bit is set. If it is then track it.
      set_bits += x & 1;

      # Right shift the bits so we can check the next one in line.
      x >>= 1; 

    # Add the number of set bits for the current chars to the total
    # distance
    distance += set_bits

  return distance
  
  
def get_keylength(ciphertext):
  lowest = None
  best_keylength = None

  for keylength in range(2, 41):
    to_average = []

    # Define the starting and ending points for the first chunk
    start = 0
    end = start + keylength
    while (1):
      # Grab 2 adjacent chunks of data that are KEYLENGTH long.
      first_chunk = ciphertext[start:end]
      second_chunk = ciphertext[start + keylength:end + keylength]

      # Check if we're at the end of ciphertext. We can ignore the
      # dangling bit.
      if (len(second_chunk) < keylength):
          break

      # Find the distance between these two KEYLENGTH chunks
      distance = hamming_distance(first_chunk, second_chunk)

      """
      "Normalize" the distance. This basically gets it to a decimal
      place that is relative to the total keylength so that it can be
      compared to distances based on other key lengths.
      """
      normalized = distance / keylength

      # We've got a score append it to the list of distances we want
      # the average of.
      to_average.append(normalized)

      # Move on to the next chunk that we'll want to get hamming
      # distances for.
      start = end + keylength
      end = start + keylength

    # Find the average of those distances and then empty out the array
    # for the next iteration.
    average = sum(to_average) / len(to_average)
    to_average = []

    # Check if we've beat the current lowest score. If we have that's
    # more likely the correct key length.
    if lowest == None or average < lowest:
      lowest = average
      best_keylength = keylength

  return best_keylength
  
  
ky = get_keylength(your_data)
  
print(ky)


def transpose_chunks_by_keylength(keylength, ciphertext):
  # Create a dictionary for the number of chunks that the data can be
  # broken into.
  chunks = dict.fromkeys(range(keylength))

  i = 0
  for octet in ciphertext:
    # If we're at the end of the key start at the beginning again. This
    # is "repeating key" XOR after all.
    if (i == keylength): i = 0

    # If the chunk is null, initialize it to an empty array.
    if (chunks[i] == None): chunks[i] = []

    # Append the current octet to the chunk.
    chunks[i].append(octet)

    i += 1

  return chunks
  
  
  
def get_key(blocks):
  common = 'ETAOIN SHRDLU'
  key = ''

  for i in blocks:
    current_high_score = 0
    current_key_char = ''

    for j in range(127):
      # Create an array of all the XOR'd
      x = [j ^ the_bytes for the_bytes in blocks[i]]
            
      # Convert the array of numbers back into bytes
      b = bytes(x)

      # Convert to a string so we can compare it to the common
      # letters.
      b_str = str(b, 'utf-8')

      # Increase the score for everywhere there is overlap
      score = 0
      for k in b_str.upper():
          if k in common:
              score += 1

      # If this score is better for this char, keep it
      if score > current_high_score:
        current_high_score = score
        current_key_char = chr(j)

    key += current_key_char

  return key
  
  
def get_key(blocks):
  common = 'ETAOIN SHRDLU'
  key = ''

  for i in blocks:
    current_high_score = 0
    current_key_char = ''

    for j in range(127):
      # Create an array of all the XOR'd
      x = [j ^ the_bytes for the_bytes in blocks[i]]
            
      # Convert the array of numbers back into bytes
      b = bytes(x)

      # Convert to a string so we can compare it to the common
      # letters.
      b_str = str(b, 'utf-8')

      # Increase the score for everywhere there is overlap
      score = 0
      for k in b_str.upper():
          if k in common:
              score += 1

      # If this score is better for this char, keep it
      if score > current_high_score:
        current_high_score = score
        current_key_char = chr(j)

    key += current_key_char

  return key
  


def decrypt(message_bytes, key):
  decrypted = b''

  i = 0
  for byte in message_bytes:
    # Go back to the beginning of the key if we've reached it's length.
    # This handles the "repeating" bit of the key.
    if (i == len(key)):
      i = 0

    # Convert the key char to a number so it can be XOR'd
    xor = byte ^ ord(key[i])
    
    # Convert the xor'd value back to bytes... bytes(...) requires an
    # array as an argument, hence the [...]
    decrypted += bytes([xor])

    i += 1

  return decrypted
  


decoded = your_data
# First we need to take a stab at finding the key length.
keylength = get_keylength(your_data)
print('kl',keylength)
# Once we have a good key length transpose the chunks
chunks = transpose_chunks_by_keylength(keylength, decoded)

# Get the key from the transposed chunks
key = get_key(chunks)
gkey=key
key = 'key'*9

# Decrypt the ciphertext
decrypted = decrypt(decoded, key)

# Find out what it is!
print(decrypted)

print('guessed key:',gkey,' ,usingkey: ',key)
  
new_data = base64.b64encode(your_data)

#print(new_data,  file=open('IRONCLAD2.autosave', 'w'))

# 
# with open ("IRONCLAD2.autosave", "r") as myfile:
#     encoded2=myfile.readlines()[0]



# now make the edits to decrypted:

dunk=999

save = str(decrypted,'ascii')
save_2 = save

part1 = save_2.split('gold": ')[0]
# part3 = save_2.split('gold": ')[1][3:]
part3 = save_2.split('gold": ')[1][len(save.split('gold": ')[1].split(',')[0]):] # only erase up to the length of the gold variable

part2 = 'gold": '+'9999'
save_2 = part1+part2+part3

part1 = save_2.split('max_health": ')[0]
part3 = save_2.split('max_health": ')[1][2:] # if prev helath was 2 digit use 2 if was 3 use 3
part2 = 'max_health": '+'999'
save_2 = part1+part2+part3

part1 = save_2.split('current_health": ')[0]
part3 = save_2.split('current_health": ')[1][2:]
part2 = 'current_health": '+'999'
save_2 = part1+part2+part3

import re

for match in re.finditer('health', save):
    print (match.start(), match.end())
    print(save_2[match.start()-7:match.end()+14])
# 
# for match in re.finditer('hp', save):
#     print (match.start(), match.end())
#     print(save_2[match.start()-7:match.end()+25])
    
# 
# for match in re.finditer('ascension', save):
#     print (match.start(), match.end())
#     print(save_2[match.start()-7:match.end()+14])
# 


#str(decrypted,'ascii').encode() == decrypted

save_3 = save_2.encode()
save_4 = base64.b64encode(decrypt(save_3,key))
# print(save_4,  file=open('IRONCLAD_edit.autosave', 'wb')) # wb to write file in binary mode

f = open(savefile.split('_')[0]+'.autosave', 'wb')
f.write(save_4)
f.close()










