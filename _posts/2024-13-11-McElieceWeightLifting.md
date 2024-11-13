---
layout: post
title: McEliece Weight Lifting - Hack.lu 2024
date: 2024-13-11 19:25:40
description: Writeup for a crypto CTF in Hack.lu 2024
tags: crypto
categories: ctf
---

# McEliece Weight Lifting

**Author:** p4pa  
**Team:** xSTF

## INFO

**CTF:** Hack.lu 2024  
**Challenge:** McEliece Weight Lifting  
**Category:** Crypto  
**Description:** Robert McEliece, our lord and savior of the gym, reveals his flag only after you lift some weights. Given the public key and ciphertext, can you find a correct error vector?

## Writeup

### Analysis

First we analyzed the provided source files. Two key files were included:

- **main.py**: This script interacts with the challenge on an external machine `nc mceliece.flu.xxx 5555`. Key functionalities include:
  1. Importing a **public key** from a file.
  2. Importing a **syndrome** (the ciphertext), which encodes the encrypted message.
  3. Defining parameters specific to the McEliece Cryptosystem, including $n$, $w$, and $t$, crucial for understanding the error-correcting code's structure and weight.
  4. Asks user for an **error vector**, and computes a new **syndrome** using the public key, and checking for a match with the original. If they match, the flag is revealed.

- **mceliece.py**: This file contains the implementation of the McEliece Cryptosystem, including functions for encoding, encrypting, and generating syndromes.

### McEliece Cryptosystem Overview

The McEliece cryptosystem is a public-key encryption scheme based on error-correcting codes. Key components include:

1. **Goppa Codes**: Central to the cryptosystem, Goppa codes are a type of linear error-correcting code designed to facilitate easy error correction while being difficult to decode without the private key.

[More on Goppa Codes](https://surface.syr.edu/cgi/viewcontent.cgi?article=1846&context=honors_capstone)

2. **Encoding and Encryption**

    - Messages are first encoded as a codeword $c = mG$ using a generator matrix $G$, and then an error vector $e$ is added through XOR.
    - The encrypted message (ciphertext) $y$ is defined as:

        ```math
        y = c \oplus e = mG \oplus e
        ```

    - Where:
        - $m $ is the original message in binary vector form.
        - $G$ is the generator matrix of the Goppa code.
        - $e$ is a chosen error vector with a fixed Hamming weight.

3. **Syndrome**:
   - The **syndrome** of a ciphertext is computed using the **parity-check matrix** $H$. For a received message $y$, the **syndrome** $s$ is calculated as:

        ```math
        s = H \cdot e
        ```

    - Here, $e$ represents the **error vector**. This equation is the key to solve this CTF! Solving this equtation in order of $e$ allows us to unveil the flag.

    Reminder that this is just the simplified explanation and I had to spend some time reading:
    [This](https://en.wikipedia.org/wiki/McEliece_cryptosystem)
    [and This](https://classic.mceliece.org/)

## Solution

### Formulating the Problem

We are provided with the **public parity-check matrix** $H$(pubkey) and a **syndrome** vector $s$(cipher). Our goal is to determine the **error vector** $e$:

```math
H \cdot e = s
```

where:

- $H$ is the known public key matrix.
- $s$ is the given syndrome (ciphertext).
- $e$ is the unknown error vector.

### Setting Up Gaussian Elimination

To solve for $e$, we need to treat the equation $H \cdot e = s$ as a **system of linear equations in binary.** We can set up this equation as an **augmented matrix** $[H | s]$ and apply a **Gaussian elimination.**:

1. **Create the Augmented Matrix**: Formulate the augmented matrix $[H | s]$.
2. **Apply Gaussian Elimination**: Perform row operations using binary arithmetic (mod 2) to transform the matrix into a simpler form, making it easier to find the entries of $e$.
3. **Back Substitution**: Once in this simpler form, back-substitute to deduce the values of $e$.

This Gaussian elimination process will return an error vector $e$ that satisfies the equation we wanted to solve $H \cdot e = s$.

```python
import numpy as np
import json
from pathlib import Path

# Load the public key and syndrome
pk = json.loads(Path("data/pubkey").read_text())
H, w = pk["P"], pk["w"]
n = len(H[0])  # n is the length of the code
k = n - len(H)  # dimension of the code

# Load the syndrome (ciphertext)
syndrome = json.loads(Path("data/secret.txt.enc").read_text())

# Convert public key and syndrome to numpy arrays
P = np.array(H, dtype=int)
syndrome_vector = np.array(syndrome, dtype=int)

# Gaussian elimination function to solve P * e = syndrome
def gaussian_elimination(P, syndrome_vector):
    # Append syndrome as the last column of P (to form an augmented matrix)
    augmented_matrix = np.hstack([P, syndrome_vector.reshape(-1, 1)])
    rows, cols = augmented_matrix.shape
    
    # Perform Gaussian elimination
    for i in range(min(rows, cols-1)):
        # Find the pivot (the first row where we have a 1 in column i)
        if augmented_matrix[i, i] == 0:
            for j in range(i+1, rows):
                if augmented_matrix[j, i] == 1:
                    augmented_matrix[[i, j]] = augmented_matrix[[j, i]]  # Swap rows
                    break
        # Eliminate all rows below the pivot
        for j in range(i+1, rows):
            if augmented_matrix[j, i] == 1:
                augmented_matrix[j] = (augmented_matrix[j] + augmented_matrix[i]) % 2  # Binary addition
    
    # Back substitution to find the solution
    error_vector = np.zeros(cols-1, dtype=int)
    for i in range(rows-1, -1, -1):
        if augmented_matrix[i, i] == 1:
            error_vector[i] = augmented_matrix[i, -1]
            # Subtract the found solution from above rows
            for j in range(i):
                if augmented_matrix[j, i] == 1:
                    augmented_matrix[j, -1] = (augmented_matrix[j, -1] - error_vector[i]) % 2
    
    return error_vector

# Solve for the error vector using Gaussian elimination
error_vector = gaussian_elimination(P, syndrome_vector)

# Write the error vector to a JSON file
with open("error_vector.json", "w") as f:
    json.dump(error_vector.tolist(), f)  # Convert NumPy array to a list and write as JSON

# Check if it matches the syndrome
if np.array_equal(np.dot(P, error_vector) % 2, syndrome_vector):
    print("Success! The error vector is correct.")
else:
    print("Error vector does not match the syndrome.")
```

After identifying the correct error vector, entering it into the challenge interface reveals the flag!