from hashlib import sha256
from time import time
from termcolor import colored

DIFFICULTY = 4

class Transaction:
    def __init__(self, from_hash, to_hash, amount, time):
        self.from_hash = from_hash
        self.to_hash = to_hash
        self.amount = amount
        self.time = time
        self.hash = self.get_hash()

    def __str__(self):
        s = colored(f"  | Transaction {self.hash[:8]}", "green") + "\n"
        s += "  | Amount " + colored(self.amount, "yellow") + "\n"
        s += "  | From " + colored(self.from_hash[:8], "yellow") + "\n"
        s += "  | To " + colored(self.to_hash[:8], "yellow") + "\n"
        s += "  | At time " + colored(self.time, "blue") + "\n"
        return s

    def get_hash(self):
        str_to_hash = self.from_hash
        str_to_hash += self.to_hash
        str_to_hash += str(self.amount)
        str_to_hash += str(self.time)
        return sha256(str_to_hash.encode("utf-8")).hexdigest()

    def validate(self):
        if self.time > time() * 1000:
            return (False, "Invalid future time")
        # TODO: Check address has valid funds
        return (True, "")


def get_merkle_root(txs):
    assert len(txs) > 0
    def hash_pair(a, b):
        # Hash a pair of transaction hashes
        return sha256((a + b).encode('utf-8')).hexdigest()

    if len(txs) == 1:
        return txs[0].hash

    tx_hashes = [tx.hash for tx in txs]
    # Reduce by pairing and hashing together
    while len(tx_hashes) > 1:
        if len(tx_hashes) % 2 == 1:
            # Make list even by duplicating the last hash
            tx_hashes.append(tx_hashes[-1])
        next_level = []
        for i in range(0, len(tx_hashes), 2):
            combined_hash = hash_pair(tx_hashes[i], tx_hashes[i+1])
            next_level.append(combined_hash)
        tx_hashes = next_level
    return tx_hashes[0]


class Block:
    def __init__(self, txs, prev_hash, time, nonce):
        self.txs = txs
        self.merkle_root = get_merkle_root(txs)
        self.prev_hash = prev_hash
        self.time = time
        self.nonce = nonce
        self.hash = self.get_hash()

    def __str__(self):
        s = colored(f"Block {self.hash[DIFFICULTY:10]}", "green") + "\n"
        s += f"hash: {self.hash[:40]}\n"
        s += f"previous hash: {self.prev_hash[:40]}\n"
        s += f"time: {self.time}\n"
        s += f"transactions: {len(self.txs)}\n"
        for tx in self.txs:
            s += str(tx)
        s += f"merkle root: {self.merkle_root[:40]}\n"
        s += f"nonce: {self.nonce}\n"
        return s

    def get_hash(self):
        str_to_hash = self.merkle_root
        str_to_hash += self.prev_hash
        str_to_hash += str(self.time)
        str_to_hash += str(self.nonce)
        return sha256(str_to_hash.encode('utf-8')).hexdigest()

    def validate(self, is_genisis=False):
        is_valid_nonce = self.hash.startswith("0"*DIFFICULTY)
        if is_genisis:
            return (True, "") if is_valid_nonce else (False, "Invalid nonce")

        if self.hash != self.get_hash():
            return (False, "Invalid self hash")
        if self.time > time() * 1000:
            return (False, "Invalid future block time")
        if self.merkle_root != get_merkle_root(self.txs):
            return (False, "Invalid merkle root")
        if not len(self.txs):
            return (False, "No transactions in block")
        for tx in self.txs:
            is_valid, reason = tx.validate()
            if not is_valid:
                return (False, f"Invalid tx: {reason}")
        return (True, "") if is_valid_nonce else (False, "Invalid nonce")



class Chain:
    def __init__(self):
        self.chain = []

    def __str__(self):
      s = ""
      for b in self.chain:
          s += str(b) + "\n"
      return s

    def add_block(self, block):
        if block.validate(is_genisis=(not len(self.chain))):
            self.chain.append(block)
        else:
            print("Cannot add invalid block!")
            print(block)

    def validate(self):
        if not self.chain:
            return (False, "No blocks in chain")

        for i, block in enumerate(self.chain):
            if i == 0:
                valid, reason = block.validate(is_genisis=True)
                if not valid:
                    return (False, f"Invalid block {i}: {reason}")
                continue

            if block.prev_hash != self.chain[i - 1].hash:
                return (False, f"Previous hash doesn't match at {i}")
            if block.time <= self.chain[i - 1].time:
                return (False, f"Time is not sequential at {i}")
            valid, reason = block.validate(is_genisis=True)
            if not valid:
                return (False, f"Invalid block {i}: {reason}")

        return (True, "")


def mine_block(transactions, prev_hash, block_time):
    print(colored("Mining block!", "green"))
    nonce = 0
    while True:
        test_block = Block(transactions, prev_hash, block_time, nonce)
        is_valid, reason = test_block.validate()
        if is_valid:
            return test_block
        else:
            print(reason)
        nonce += 1
        if nonce % 10000 == 0:
            print(f"Tried {nonce} nonces...")

def create_new_transaction(from_hash, to_hash, amount):
    tx_time = time() * 1000
    return Transaction(from_hash, to_hash, amount, tx_time)


def main():
    GENISIS_TIME = 1742499503227
    GENISIS_ADDR = sha256("GENISIS".encode("utf-8")).hexdigest()
    ELGIN_ADDR = sha256("ELGINBELOY".encode("utf-8")).hexdigest()
    RESERVE_ADDR = sha256("RESERVE".encode("utf-8")).hexdigest()
    genisis_transactions = []
    genisis_transactions.append(
        Transaction(GENISIS_ADDR, ELGIN_ADDR, 100, GENISIS_TIME))
    genisis_transactions.append(
        Transaction(GENISIS_ADDR, RESERVE_ADDR, 100, GENISIS_TIME))
    genisis_nonce = 0
    genisis_block = Block(
        genisis_transactions,
        "genisis",
        GENISIS_TIME+1,
        genisis_nonce
    )
    valid, reason = genisis_block.validate(is_genisis=True)
    while not valid:
        genisis_nonce += 1
        discover_probability = 1 - ((((16**DIFFICULTY)-1)/(16**DIFFICULTY))**genisis_nonce)
        print(f"Nonce {genisis_nonce}")
        print(f"   discover probability now at {discover_probability}")
        genisis_block = Block(
            genisis_transactions,
            "genisis",
            GENISIS_TIME+1,
            genisis_nonce
        )
        valid, reason = genisis_block.validate(is_genisis=True)
    if not valid:
        print(colored("Invalid Genisis Block", "red"))
        print(reason)
    chain = Chain()
    chain.add_block(genisis_block)
    valid, reason = chain.validate()
    if not valid:
        print(colored("Invalid Chain", "red"))
        print(reason)
    print(chain)

    transactions = []
    while True:
        print("1 - make new transaction")
        print("2 - create new block")
        print("3 - print chain")
        print("4 - print block")
        user_input = input(colored(":", "green"))
        if user_input == "1":
            transactions.append(
                create_new_transaction(ELGIN_ADDR, RESERVE_ADDR, 10))
            for tx in transactions:
                print(tx)
        elif user_input == "2":
            new_block = mine_block(transactions[:], chain.chain[-1].hash, time() * 1000)
            chain.add_block(new_block)
            transactions = []
        elif user_input == "3":
            print(str(chain))
        elif user_input == "4":
            user_input = input(colored("index :", "yellow"))
            print(str(chain[i]))
if __name__ == "__main__":
    main()
