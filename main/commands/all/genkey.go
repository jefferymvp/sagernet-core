package all

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"

	"github.com/v2fly/v2ray-core/v5/main/commands/base"
)

var cmdGenKey = &base.Command{
	UsageLine: "{{.Exec}} genkey",
	Short:     "generate new key",
	Long: `Generate new new 32bit base64 encoded key.
`,
	Run: executeGenKey,
}

func executeGenKey(cmd *base.Command, args []string) {
	key := make([]byte, 32)
	io.ReadFull(rand.Reader, key)
	fmt.Println(base64.StdEncoding.EncodeToString(key))
}
