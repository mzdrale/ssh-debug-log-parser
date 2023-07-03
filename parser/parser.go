package parser

import (
	"bufio"
	"os"
	"sort"
	"strings"

	"github.com/oriser/regroup"
	c "gitlab.com/mzdrale/ssh-debug-log-parser/config"
)

// User - holds user login info
type User struct {
	Username               string
	RemoteIPs              []string
	AuthMethods            []string
	RemoteProtocolVersions []string
	RemoteSoftwareVersions []string
	KexAlgorithms          []string
	KexHostKeyAlgorithms   []string
	KexClientServerCiphers []string
	KexServerClientCiphers []string
	FailedLoginsFrom       []string
}

// SSHConnection - holds SSH connection info
type SSHConnection struct {
	Username              string `regroup:"Username"`
	Time                  string `regroup:"Time"`
	PID                   string `regroup:"PID"`
	Host                  string `regroup:"Host"`
	RemoteIP              string `regroup:"RemoteIP"`
	RemotePort            string `regroup:"RemotePort"`
	RemoteProtocolVersion string `regroup:"RemoteProtocolVersion"`
	RemoteSoftwareVersion string `regroup:"RemoteSoftwareVersion"`
	KexAlgorithm          string `regroup:"KexAlgorithm"`
	KexHostKeyAlgorithm   string `regroup:"KexHostKeyAlgorithm"`
	KexClientServerCipher string `regroup:"KexClientServerCipher"`
	KexServerClientCipher string `regroup:"KexServerClientCipher"`
	AuthMethod            string `regroup:"AuthMethod"`
	FailedLoginFrom       string `regroup:"FailedLoginFrom"`
}

var Cfg c.Config

func ReadLogFiles(filepaths []string) ([]string, error) {
	var lines []string

	for _, file := range filepaths {
		readFile, err := os.Open(file)

		if err != nil {
			return []string{}, err
		}

		fileScanner := bufio.NewScanner(readFile)

		fileScanner.Split(bufio.ScanLines)

		for fileScanner.Scan() {
			lines = append(lines, fileScanner.Text())
		}

		readFile.Close()
	}

	return lines, nil
}

func Parse(lines []string) (map[string]*SSHConnection, error) {
	var pid string

	logMap := make(map[string]*SSHConnection)

	// We need to iterate twice, first time to get PID and
	// create empty record with PID as key
	for _, line := range lines {
		r := regroup.MustCompile(`^(?P<Time>\S{3}\s+\S+\s+\S+)\s+(?P<Host>\S+)\s+sshd\[(?P<PID>\d+)\]:\s+`)
		m, _ := r.Groups(line)

		// PID
		if m["PID"] != "" {
			logMap[m["PID"]] = &SSHConnection{}
		}
	}

	// Second iteration - parse lines and populate map
	for _, line := range lines {
		// Let's get ForkPID, RemoteIP and RemotePort.
		// We need ForkID as connection ID.
		r := regroup.MustCompile(`^(?P<Time>\S{3}\s+\S+\s+\S+)\s+(?P<Host>\S+)\s+sshd\[(?P<PID>\d+)\]:\s+Connection from (?P<RemoteIP>\S+)\s+port\s+(?P<RemotePort>\S+)\s+`)
		m, _ := r.Groups(line)

		// PID
		if m["PID"] != "" {
			pid = m["PID"]
			logMap[pid].PID = pid
		}

		// Time
		if m["Time"] != "" {
			logMap[pid].Time = m["Time"]
		}

		if m["Host"] != "" {
			logMap[pid].Host = m["Host"]
		}

		if m["RemoteIP"] != "" {
			logMap[pid].RemoteIP = m["RemoteIP"]
		}

		if m["RemotePort"] != "" {
			logMap[pid].RemotePort = m["RemotePort"]
		}

		// RemoteProtocolVersion and RemoteSoftwareVersion regex
		r = regroup.MustCompile(`^(?P<Time>\S{3}\s+\S+\s+\S+)\s+(?P<Host>\S+)\s+sshd\[(?P<PID>\d+)\]:\s+\S+:\s+Remote protocol version (?P<RemoteProtocolVersion>\S+), remote software version (?P<RemoteSoftwareVersion>.*)`)
		m, _ = r.Groups(line)

		// if err != nil {
		// 	fmt.Println(err)
		// }

		if m["RemoteProtocolVersion"] != "" {
			logMap[pid].RemoteProtocolVersion = m["RemoteProtocolVersion"]
		}

		if m["RemoteSoftwareVersion"] != "" {
			logMap[pid].RemoteSoftwareVersion = m["RemoteSoftwareVersion"]
		}

		// KexAlgorithm regex
		r = regroup.MustCompile(`^(?P<Time>\S{3}\s+\S+\s+\S+)\s+(?P<Host>\S+)\s+sshd\[(?P<PID>\d+)\]:\s+\S+:\s+kex: algorithm:\s+(?P<KexAlgorithm>\S+)\s+\[`)
		m, _ = r.Groups(line)

		// if err != nil {
		// 	fmt.Println(err)
		// }

		if m["KexAlgorithm"] != "" {
			logMap[pid].KexAlgorithm = m["KexAlgorithm"]
		}

		// KexHostKeyAlgorithm regex
		r = regroup.MustCompile(`^(?P<Time>\S{3}\s+\S+\s+\S+)\s+(?P<Host>\S+)\s+sshd\[(?P<PID>\d+)\]:\s+\S+:\s+kex: host key algorithm:\s+(?P<KexHostKeyAlgorithm>\S+)\s+\[`)
		m, _ = r.Groups(line)

		// if err != nil {
		// 	fmt.Println(err)
		// }

		if m["KexHostKeyAlgorithm"] != "" {
			logMap[pid].KexHostKeyAlgorithm = m["KexHostKeyAlgorithm"]
		}

		// KexClientServerCipher regex
		r = regroup.MustCompile(`^(?P<Time>\S{3}\s+\S+\s+\S+)\s+(?P<Host>\S+)\s+sshd\[(?P<PID>\d+)\]:\s+\S+:\s+kex: client->server cipher:\s+(?P<KexClientServerCipher>\S+)\s+MAC`)
		m, _ = r.Groups(line)

		// if err != nil {
		// 	fmt.Println(err)
		// }

		if m["KexClientServerCipher"] != "" {
			logMap[pid].KexClientServerCipher = m["KexClientServerCipher"]
		}

		// KexServerClientCipher regex
		r = regroup.MustCompile(`^(?P<Time>\S{3}\s+\S+\s+\S+)\s+(?P<Host>\S+)\s+sshd\[(?P<PID>\d+)\]:\s+\S+:\s+kex: server->client cipher:\s+(?P<KexServerClientCipher>\S+)\s+MAC`)
		m, _ = r.Groups(line)

		// if err != nil {
		// 	fmt.Println(err)
		// }

		if m["KexServerClientCipher"] != "" {
			logMap[pid].KexServerClientCipher = m["KexServerClientCipher"]
		}

		// Username regex
		r = regroup.MustCompile(`^(?P<Time>\S{3}\s+\S+\s+\S+)\s+(?P<Host>\S+)\s+sshd\[(?P<PID>\d+)\]:\s+\S+:\s+userauth-request for user (?P<Username>\S+)\s+service ssh-connection method (?P<AuthMethod>\S+)\s+`)
		m, _ = r.Groups(line)

		// if err != nil {
		// 	fmt.Println(err)
		// }

		if strings.TrimSpace(m["Username"]) != "" {
			logMap[pid].Username = m["Username"]
		}

		if m["AuthMethod"] != "" {
			logMap[pid].AuthMethod = m["AuthMethod"]
		}

		// FailedLoginFrom login regex
		r = regroup.MustCompile(`^\S{3}\s+\S+\s+\S+\s+\S+\s+sshd\[(?P<PID>\d+)\]:\s+(Failed (password|publickey) for|Invalid user)\s+(?P<User>\S+)\s+from\s+(?P<FailedLoginFrom>\S+)\s+port\s+(?P<Port>\S+)\s+`)
		m, _ = r.Groups(line)

		// if err != nil {
		// 	fmt.Println(err)
		// }

		if strings.TrimSpace(m["User"]) != "" {
			logMap[pid].Username = m["User"]
		}

		if m["FailedLoginFrom"] != "" {
			logMap[pid].FailedLoginFrom = m["FailedLoginFrom"]
		}

	}

	return logMap, nil
}

func PopulateUsers(logMap map[string]*SSHConnection) (map[string]User, error) {
	usersMap := make(map[string]User)

	// fmt.Printf("%#v\n", Cfg)
	// os.Exit(1)

	keys := make([]string, 0, len(logMap))

	for k := range logMap {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	// for key, element := range logMap {
	for _, key := range keys {
		element := logMap[key]
		ignore := false

		if !ignore && element.Username != "" {
			usersMap[element.Username] = User{
				Username:               element.Username,
				RemoteIPs:              addElement(usersMap[element.Username].RemoteIPs, element.RemoteIP),
				AuthMethods:            addElement(usersMap[element.Username].AuthMethods, element.AuthMethod),
				RemoteProtocolVersions: addElement(usersMap[element.Username].RemoteProtocolVersions, element.RemoteProtocolVersion),
				RemoteSoftwareVersions: addElement(usersMap[element.Username].RemoteSoftwareVersions, element.RemoteSoftwareVersion),
				KexAlgorithms:          addElement(usersMap[element.Username].KexAlgorithms, element.KexAlgorithm),
				KexHostKeyAlgorithms:   addElement(usersMap[element.Username].KexHostKeyAlgorithms, element.KexHostKeyAlgorithm),
				KexClientServerCiphers: addElement(usersMap[element.Username].KexClientServerCiphers, element.KexClientServerCipher),
				KexServerClientCiphers: addElement(usersMap[element.Username].KexServerClientCiphers, element.KexServerClientCipher),
				FailedLoginsFrom:       addElement(usersMap[element.Username].FailedLoginsFrom, element.FailedLoginFrom),
			}
		}
	}

	return usersMap, nil
}

func addElement(elements []string, element string) []string {

	element_exists := false
	for _, el := range elements {
		if el == element {
			element_exists = true
		}
	}

	if !element_exists && element != "" {
		elements = append(elements, element)
	}
	return elements
}
