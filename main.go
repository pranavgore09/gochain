package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"time"

	"github.com/kataras/iris"
	"github.com/kataras/iris/middleware/logger"
	"github.com/kataras/iris/middleware/recover"
	uuid "github.com/satori/go.uuid"
)

type Blockchain struct {
	chain               []*Block
	currentTransactions []Transaction
	nodes               map[string]struct{}
}

type Block struct {
	Index         int
	Timestamp     int64
	Transactions  []Transaction
	Proof         int
	Previous_hash string
}

type Transaction struct {
	Sender    string `json:"sender"`
	Recipient string `json:"recipient"`
	Amount    int    `json:"amount"`
}

type NodeRegistration struct {
	Nodes []string `json:"nodes"`
}

func NewBlockchain() *Blockchain {
	b := Blockchain{}
	genesisHash := sha256.New()
	genesisHash.Write([]byte("genesis"))
	genesisHashString := hex.EncodeToString(genesisHash.Sum(nil))
	b.newBlock(genesisHashString, 100)
	fmt.Println("-------------------- genesis hash", genesisHashString)
	b.nodes = make(map[string]struct{})
	return &b
}

func (b *Blockchain) newBlock(previous_hash string, proof int) *Block {
	if previous_hash == "" {
		previous_hash = HashBlock(b.lastBlock()) // TBD
	}

	nb := Block{
		Index:         len(b.chain) + 1,
		Timestamp:     time.Now().UnixNano(),
		Transactions:  b.currentTransactions,
		Proof:         proof,
		Previous_hash: previous_hash,
	}

	b.currentTransactions = nil
	b.chain = append(b.chain, &nb)
	fmt.Printf("\nnew block :: %v\n", nb)
	return &nb
}

func (b *Blockchain) newTransaction(sender string, recipient string, amount int) int {
	ct := Transaction{
		Sender:    sender,
		Recipient: recipient,
		Amount:    amount,
	}
	b.currentTransactions = append(b.currentTransactions, ct)
	l := b.lastBlock()
	return l.Index + 1
}

func (b *Blockchain) proofOfWork(lastProof int) int {
	proof := 0
	for validProof(lastProof, proof) == false {
		proof++
	}
	return proof
}

func validProof(lastProof int, proof int) bool {
	answer := []byte{0}
	guess := lastProof * proof
	guessHash := sha256.Sum256([]byte(fmt.Sprintf("%d", guess)))
	return bytes.Equal(answer, guessHash[len(guessHash)-1:])
}

func (b *Blockchain) registerNode(addr string) {
	parsedAddr, err := url.Parse(addr)
	if err != nil {
		fmt.Printf("\n\nUnable to register wrong URL : %s \n\n", addr)
		return
	}
	x := parsedAddr.String()
	b.nodes[x] = struct{}{}
}

func (b *Blockchain) resolveConflict() bool {
	neighbours := b.nodes
	var newChain []*Block
	changed := false
	maxLen := len(b.chain)
	type response struct {
		Chain  []*Block
		Length int
	}
	for url := range neighbours {
		resp, err := http.Get(url + "/chain")
		if err != nil {
			fmt.Printf("\n Unalbe to read from node : %s \n", url)
			continue
		}
		defer resp.Body.Close()
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			fmt.Printf("\n Unalbe to parse body from node : %s %v \n", url, body)
			continue
		}
		var r response
		err = json.Unmarshal(body, &r)
		if err != nil {
			fmt.Printf("\n Unalbe to unmarshal body from node : %s %v \n", url, body)
			continue
		}
		if r.Length > maxLen && ValidChain(r.Chain) {
			maxLen = r.Length
			newChain = r.Chain
			changed = true
			fmt.Println("wooooooooo - updated", maxLen)
		}
	}
	if changed {
		fmt.Println("Yes updating our chain now...")
		b.chain = newChain
		return true
	}
	return false
}

func (b *Blockchain) lastBlock() Block {
	x := b.chain[len(b.chain)-1]
	return *x
}

func ValidChain(bc []*Block) bool {
	l := len(bc)
	if l == 0 {
		return false
	}
	lb := bc[0]
	index := 1
	fmt.Println("validating.....")
	for index < l {
		bl := bc[index]
		fmt.Println("\n------------\n")
		fmt.Printf("\nlast block :: %v\n", lb)
		fmt.Printf("\n block :: %#v\n", bl)
		fmt.Println("\n------------\n")
		if bl.Previous_hash != HashBlock(*lb) {
			fmt.Println("hash did not match", bl.Previous_hash, "___", HashBlock(*lb))
			return false
		}
		if !validProof(lb.Proof, bl.Proof) {
			fmt.Println("Proof is invalid")
			return false
		}
		lb = bl
		index++
	}
	return true
}

func HashBlock(b Block) string {
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

		// previousHash := HashBlock(lb)
		block := bc.newBlock("", proof)

		type Resp struct {
			Message      string
			BlockIndex   int
			Transaction  []Transaction
			Proof        int
			PreviousHash string
		}
		response := Resp{
			Message:      "New Block Forged",
			BlockIndex:   block.Index,
			Transaction:  block.Transactions,
			Proof:        block.Proof,
			PreviousHash: block.Previous_hash,
		}
		ctx.JSON(response)
	})

	// Method:   GET
	// Resource: http://localhost:5000/chain
	app.Get("/chain", func(ctx iris.Context) {
		ctx.JSON(iris.Map{"chain": bc.chain, "length": len(bc.chain)})
	})

	// Method:   POST
	// Resource: http://localhost:5000/nodes/register
	app.Post("/nodes/register", func(ctx iris.Context) {
		var reg NodeRegistration
		ctx.ReadJSON(&reg)
		if len(reg.Nodes) == 0 {
			ctx.JSON(iris.Map{"error": "Empty list of nodes"})
			return
		}
		for _, url := range reg.Nodes {
			bc.registerNode(url)
		}
		ctx.JSON(iris.Map{"message": "new nodes are registered", "nodes": bc.nodes})
	})

	// Method:   GET
	// Resource: http://localhost:5000/nodes/resolve
	app.Get("/nodes/resolve", func(ctx iris.Context) {
		replaced := bc.resolveConflict()
		type Resp struct {
			Message string
			Chain   []*Block
		}
		var r Resp
		r.Chain = bc.chain
		if replaced {
			r.Message = "our chain was replaced"
		} else {
			r.Message = "our chain is authoritative"
		}
		ctx.JSON(r)
	})

	// http://localhost:5000
	// http://localhost:5000/ping
	// http://localhost:5000/hello
	var port string
	flag.StringVar(&port, "port", "5000", "port value in string")
	flag.Parse()
	app.Run(iris.Addr(":"+port), iris.WithoutServerError(iris.ErrServerClosed))
}
