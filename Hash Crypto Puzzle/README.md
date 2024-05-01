# Hash-Based Crypto Puzzle Solver

This Python script implements a hash-based crypto puzzle using the SHA-256 hashing algorithm. The script generates a random puzzle `P` of `B` bits and challenges to find a message `M` that, when hashed using SHA-256, yields the last `B` bits equal to `P`. The time taken to find such a `M` is measured and averaged over multiple trials. The results are then plotted to show the relationship between the bit length `B` and the average time taken to solve the puzzle.

## Requirements

- Python 3.6 or higher
- matplotlib library

## Usage

1. Clone the repository to your local machine.
2. Run the script using Python 3.6 or higher.

```bash
python3 crypto_puzzle.py