import * as crypto from "crypto";

// The transaction defines transferring money between two wallets
class Transaction {
    constructor(
        public amount: number,
        public player: string, //public key
        public payee: string   //public key
    ){}

    //Will turn into string and help make dealing with the cryptographic 
    //objects easier
    toString() {
        return JSON.stringify(this);
    }
}


// Block is a container for multiple transactions - can think of a block as an element
// in an array or more appropiately as a LINKED LIST
class Block {

    // One time use random number (for proof of work POW)
    public nonce = Math.round(Math.random()*999999999)

    constructor(
        public prevHash: string | null, //link to the previous block
        public transaction: Transaction,
        public ts = Date.now() //timestamp of when instance of block instantiated 
    ){}

    get hash() {
        // turn into JSON string first
        const str = JSON.stringify(this); 
        //use crypto method to get hash of it
        const hash = crypto.createHash("SHA256");
        // apply the hashing function to our string
        hash.update(str).end();
        // return hash value/digest as a hexadecimal string
        return hash.digest("hex");
    }
}


// Chain is a long list of blocks
class Chain {
    // Below is to ensure that there is only one blockchain by making it a singleton
    // instance a setting a static instance property
    // one time use random number 
    public static instance = new Chain();

    chain: Block[]; // i.e. the chain is an array of Block types

    constructor() {
        // set up the first block in our block chain and call it genesis sending 100 coins to satoshi, 
        // the previous hash is null because there was nothing before it
        this.chain = [new Block(null, new Transaction(100, "genesis", "satoshi"))];
    }

    get lastBlock() {
        return this.chain[this.chain.length - 1];
    }

    // Our dummy Proof Of Work method
    // this method takes the nonce and runs a while loop till a hash is created with 
    // four zeros - i.e. essentially with a brute force approach 
    mine(nonce: number) {

        let solution = 1;
        console.log("⛏️ ⛏️ ⛏️ mining...");

        while(true){
            const hash = crypto.createHash("MD5"); //Message-Digest algorithm - similar to SHA256 but MD5 is only 128bits and therefore also faster to compute
            hash.update((nonce + solution).toString()).end();

            const attempt = hash.digest("hex");

            if(attempt.substr(0,4) === "0000") {
                console.log(`Solved: ${solution}`);
                // if found then we return the solution - thereby exiting the while loop 
                // and allowing us to also "verify" then
                return solution;
            }

            solution +=1;
        }
    }

    addBlock(transaction: Transaction, senderPublicKey: string, signature: Buffer) {
        const verifier = crypto.createVerify("SHA256");
        verifier.update(transaction.toString());

        const isValid = verifier.verify(senderPublicKey, signature);

        // add to blockchain is sender is verified 
        if(isValid) {
            const newBlock = new Block(this.lastBlock.hash, transaction);
            // before pushing - add our simple POW system to avoid double addition of the same transaction
            this.mine(newBlock.nonce);

            this.chain.push(newBlock);
        }
    }
}


// Allow to securely send coin back and forth 
// Wallet is essentially just a wrapper for a public key
// and a private key 
class Wallet {  
    public publicKey: string; //Public key is for recieving money 
    public privateKey: string; //Private key is for spending money 

    constructor(){
        // generate a new assymetric public-private key pair using rsa encyption algorithm
        // Public key is used to ENCRYPT and Private key to DECRYPT 
        // We can use this for the SIGNATURE when adding new coins i.e. new BLOCK by SIGNING the 
        // hash with our Private key and verify later with our public key
        const keyPair = crypto.generateKeyPairSync("rsa", {
        //Format key into string with below formatting options
        modulusLength: 2048,
        publicKeyEncoding: { type: "spki", format: "pem" },
        privateKeyEncoding: { type: "pkcs8", format: "pem" }
        })

        this.privateKey = keyPair.privateKey;
        this.publicKey = keyPair.publicKey;
    }

    sendMoney(amount: number, payeePublicKey: string) {
        const transaction = new Transaction(amount, this.publicKey, payeePublicKey);
        
        const sign = crypto.createSign("SHA256");
        sign.update(transaction.toString()).end();

        // create signature by signing with private key - like a one-time password 
        // allows us to verify our identity with the private key without actually exposing 
        // they private key - it can then be verified later with the public key
        const signature = sign.sign(this.privateKey);
        
        // attempting to add to blockchain!
        Chain.instance.addBlock(transaction, this.publicKey, signature);

    }
}


// ______________________________________
// Example use
// ______________________________________

// Create new wallets for a couple of users
const satoshi = new Wallet();
const omid = new Wallet(); 
const arslanAlp = new Wallet();

satoshi.sendMoney(17, omid.publicKey);
omid.sendMoney(10, arslanAlp.publicKey);
arslanAlp.sendMoney(5, omid.publicKey);

console.log(Chain.instance);

