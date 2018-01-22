package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/kataras/iris"
	"github.com/kataras/iris/middleware/logger"
	"github.com/kataras/iris/middleware/recover"
	uuid "github.com/satori/go.uuid"
)

type Blockchain struct {
	chain               []*Block
	currentTransactions []*Transaction
}

type Block struct {
	index         int
	timestamp     time.Time
	transactions  []*Transaction
	Proof         int
	previous_hash string
}

type Transaction struct {
	Sender    string `json:"sender"`
	Recipient string `json:"recipient"`
	Amount    int    `json:"amount"`
}

func NewBlockchain() *Blockchain {
	b := Blockchain{}
	genesisHash := sha256.New()
	genesisHash.Write([]byte("genesis"))
	genesisHashString := hex.EncodeToString(genesisHash.Sum(nil))
	b.newBlock(genesisHashString, 100)
	return &b
}

func (b *Blockchain) newBlock(previous_hash string, proof int) *Block {
	nb := Block{
		index:        len(b.chain) + 1,
		timestamp:    time.Now(),
		transactions: b.currentTransactions,
		Proof:        proof,
	}
	if previous_hash == "" {
		nb.previous_hash = HashBlock(b.lastBlock()) // TBD
	}

	b.currentTransactions = nil
	b.chain = append(b.chain, &nb)
	return &nb
}

func (b *Blockchain) newTransaction(sender string, recipient string, amount int) int {
	ct := Transaction{
		Sender:    sender,
		Recipient: recipient,
		Amount:    amount,
	}
	b.currentTransactions = append(b.currentTransactions, &ct)
	l := b.lastBlock()
	return l.index + 1
}

func (b *Blockchain) proofOfWork(lastProof int) int {
	proof := 0
	for b.validProof(lastProof, proof) == false {
		proof++
	}
	return proof
}

func (b *Blockchain) validProof(lastProof int, proof int) bool {
	answer := []byte{0}
	guess := lastProof * proof
	guessHash := sha256.Sum256([]byte(fmt.Sprintf("%d", guess)))
	return bytes.Equal(answer, guessHash[len(guessHash)-1:])
}

func (b *Blockchain) lastBlock() *Block {
	return b.chain[len(b.chain)-1]

}

func HashBlock(b *Block) string {
	newHash := sha256.New()
	newHash.Write([]byte(fmt.Sprintf("%#v", b)))
	newHashString := hex.EncodeToString(newHash.Sum(nil))
	return newHashString
}

func main() {
	fmt.Println("hello")

	// Generate a globally unique address for this node
	nodeID := uuid.NewV4()
	bc := NewBlockchain()

	app := iris.New()
	app.Logger().SetLevel("debug")
	// Optionally, add two built'n handlers
	// that can recover from any http-relative panics
	// and log the requests to the terminal.
	app.Use(recover.New())
	app.Use(logger.New())

	// Method:   GET
	// Resource: http://localhost:5000/hello
	app.Get("/hello", func(ctx iris.Context) {
		ctx.JSON(iris.Map{"message": "Hello Iris!"})
	})

	app.Post("/transactions/new", func(ctx iris.Context) {
		var trans Transaction
		ctx.ReadJSON(&trans)
		index := bc.newTransaction(trans.Sender, trans.Recipient, trans.Amount)
		msg := fmt.Sprintf("%s is sending %d to %s", trans.Sender, trans.Amount, trans.Recipient)
		type Resp struct {
			Message    string
			BlockIndex int
		}

		resp := Resp{
			Message:    msg,
			BlockIndex: index,
		}
		ctx.JSON(resp)
	})

	app.Get("/mine", func(ctx iris.Context) {
		//  We run the proof of work algorithm to get the next proof...
		lb := bc.lastBlock()
		lp := lb.Proof
		proof := bc.proofOfWork(lp)

		// reward for us
		bc.newTransaction("0", nodeID.String(), 1)

		previousHash := HashBlock(lb)
		block := bc.newBlock(previousHash, proof)

		type Resp struct {
			Message      string
			BlockIndex   int
			Transaction  []*Transaction
			Proof        int
			PreviousHash string
		}
		response := Resp{
			Message:      "New Block Forged",
			BlockIndex:   block.index,
			Transaction:  block.transactions,
			Proof:        block.Proof,
			PreviousHash: block.previous_hash,
		}
		ctx.JSON(response)
	})

	// Method:   GET
	// Resource: http://localhost:5000/chain
	app.Get("/chain", func(ctx iris.Context) {
		ctx.JSON(iris.Map{"chain": bc.chain, "length": len(bc.chain)})
	})

	// http://localhost:5000
	// http://localhost:5000/ping
	// http://localhost:5000/hello
	app.Run(iris.Addr(":5000"), iris.WithoutServerError(iris.ErrServerClosed))
}
