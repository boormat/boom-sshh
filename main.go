package main

import (
	"fmt"
	"io"

	"log"
	"net"
	"os"
	"os/user"
	"path"
	"path/filepath"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

type myExtendedAgent struct {
	agent.Agent
	histfile io.Writer // file to write bash history-ish format to.
}

// Check that my struct implements the interfaces properly.  (otherwise will be ignored silently in agent module)
func testTypes() {
	var _ agent.Agent = myExtendedAgent{}               // Verify that T implements I.
	var _ agent.Agent = (*myExtendedAgent)(nil)         // Verify that *T implements I.
	var _ agent.ExtendedAgent = myExtendedAgent{}       // Verify that T implements I.
	var _ agent.ExtendedAgent = (*myExtendedAgent)(nil) // Verify that *T implements I.
}

// Don't care pass to base impl
func (r myExtendedAgent) SignWithFlags(key ssh.PublicKey, data []byte, flags agent.SignatureFlags) (*ssh.Signature, error) {
	log.Println("Hey got some (sign request)", key)
	return r.Sign(key, data)
}

type historyMsgContent struct {
	Command  string
	Hostname string
	User     string
}

// In the case of success, since [PROTOCOL.agent] section 4.7 specifies that the contents
// of the response are unspecified (including the type of the message), the complete
// response will be returned as a []byte slice, including the "type" byte of the message.
func (r myExtendedAgent) Extension(extensionType string, contents []byte) ([]byte, error) {
	log.Print("Extension fired:", extensionType, contents)
	switch extensionType {
	case "HISTORY":
		// parse the contents.  3 Strings is expected, command, hostname, userid.
		var req historyMsgContent
		if err := ssh.Unmarshal(contents, &req); err != nil {
			log.Print("Bad Extension Message:", extensionType, contents, err)
			return nil, err
		}

		ts := time.Now()

		// write timestamp and other meta
		if _, err := r.histfile.Write([]byte(fmt.Sprintf("#%d %s %s\n", ts.Unix(), req.Hostname, req.User))); err != nil {
			log.Fatal(err)
		}
		if _, err := r.histfile.Write([]byte(fmt.Sprintln(req.Command))); err != nil {
			log.Fatal(err)
		}

	default:
		log.Print("Unknown Extension Type:", extensionType, contents)
		return nil, agent.ErrExtensionUnsupported
	}

	return []byte(""), nil
}

func main() {
	var pipeFile string
	pid := os.Getpid()
	pipeFile, testmode := os.LookupEnv("TEST_SSH_AUTH_SOCK")
	if !testmode {

		// Create the real SSH Agent Named Pipe
		tmpDir, err := os.MkdirTemp("", "ssh-go")
		if err != nil {
			log.Fatal(err)
		}
		defer os.RemoveAll(tmpDir)

		pipeFile = filepath.Join(tmpDir, fmt.Sprint("agent.", pid))
		defer os.Remove(pipeFile)
	} else {
		_ = os.Remove(pipeFile) // test mode
	}
	listener, err := net.Listen("unix", pipeFile)
	if err != nil {
		log.Fatal(err)
	}
	defer listener.Close()
	log.Println("Listening to", pipeFile)

	// config time
	histfilename := os.Getenv("AGENT_HISTFILE")
	if histfilename == "" {
		usr, err := user.Current()
		if err != nil {
			log.Fatal(err)
		}
		histfilename = path.Join(usr.HomeDir, ".history_all")
	}

	hf, err := os.OpenFile(histfilename, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		log.Fatal("Could not create/open history file: ", err)
	}
	defer hf.Close()

	myExt := myExtendedAgent{agent.NewKeyring(), hf}
	// Output the ssh-agent compatible env vars for evaling.
	fmt.Printf("SSH_AUTH_SOCK=%s; export SSH_AUTH_SOCK;\n", pipeFile)
	fmt.Printf("SSH_AGENT_PID=%d; export SSH_AGENT_PID;\n", pid)
	fmt.Printf("echo Agent pid %d;\n", pid)

	// wait for clients...
	for {
		con, err := listener.Accept()
		if err != nil {
			log.Fatal(err)
		}
		log.Println("new Connection", con)
		handleClient(myExt, con) // should be a go sub?
	}
}

func handleClient(a myExtendedAgent, connection net.Conn) {
	defer println("closed", connection)
	defer connection.Close()
	err := agent.ServeAgent(a, connection)
	if err != nil && err != io.EOF {
		// EOF is expected.
		log.Print("Error: ServeAgent :", err)
	}
}
