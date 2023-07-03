package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"strings"
	"time"

	"github.com/briandowns/spinner"
	"github.com/jedib0t/go-pretty/v6/table"
	flag "github.com/spf13/pflag"
	"github.com/spf13/viper"
	p "gitlab.com/mzdrale/ssh-debug-log-parser/parser"
)

var (
	binName string
	version string
)

// Argument variables
var (
	aPrintVersion                bool
	aPrintAll                    bool
	aPrintRemoteIPs              bool
	aPrintFailedLogins           bool
	aPrintKexClientServerCiphers bool
	aPrintKexServerClientCiphers bool
	aOutputFormat                string
	aLogFiles                    string
)

// Config variables
var (
	cLogFiles        []string
	cIgnoreRemoteIPs []string
	cIgnoreUsers     []string
	cOutputJsonFile  string
)

// var cfg config.Config

func init() {
	// Configuration dir
	cfgDir := "./"
	viper.SetConfigName("config")
	viper.SetConfigType("yaml")
	viper.AddConfigPath(cfgDir)

	// Try to read config
	if err := viper.ReadInConfig(); err != nil {
		fmt.Printf(p.Fatal("\U00002717 Unable to read configuration file: %s\n\n"), err.Error())
		os.Exit(1)
	}

	// Usage
	flag.Usage = func() {
		fmt.Printf("Usage: \n")
		flag.PrintDefaults()
	}

	// Get arguments
	flag.StringVarP(&aLogFiles, "log-files", "f", "", "Log files to parse, comma separated list")
	flag.StringVarP(&aOutputFormat, "output-format", "o", "list", "Output format (list, table, json-file)")
	flag.BoolVarP(&aPrintVersion, "version", "V", false, "Print version")
	flag.BoolVarP(&aPrintAll, "print-all", "a", false, "Print all info")
	flag.BoolVarP(&aPrintRemoteIPs, "print-remote-ips", "", false, "Print remote IP addresses")
	flag.BoolVarP(&aPrintFailedLogins, "print-failed-logins", "", false, "Print failed login IP addresses")
	flag.BoolVarP(&aPrintKexClientServerCiphers, "print-client-ciphers", "", false, "Print KexClientServerCiphers")
	flag.BoolVarP(&aPrintKexServerClientCiphers, "print-server-ciphers", "", false, "Print KexServerClientCiphers")

	if aLogFiles != "" {
		cLogFiles = strings.Split(aLogFiles, ",")
	} else {
		cLogFiles = viper.GetStringSlice("log_files")
	}

	cIgnoreRemoteIPs = viper.GetStringSlice("ignore.ips")
	cIgnoreUsers = viper.GetStringSlice("ignore.users")
	cOutputJsonFile = viper.GetString("output.json_file")

	flag.Parse()
}

// Main
func main() {

	// Print version
	if aPrintVersion {
		fmt.Printf("\n%v version %v\n\n", p.Teal(binName), p.Yellow(version))
		fmt.Printf("Config file: %s\n", p.Yellow(viper.ConfigFileUsed()))
		fmt.Printf("URL: %s\n\n", p.Yellow("https://gitlab.com/mzdrale/ssh-debug-log-parser"))
		os.Exit(0)
	}

	// fmt.Println("Startaaaa")

	// Cfg := &config.Config{
	// 	IgnoreRemoteIPs: cIgnoreRemoteIPs,
	// 	IgnoreUsers:     cIgnoreUsers,
	// }

	// fmt.Printf("%#v\n", Cfg)

	fmt.Printf("\U00002139 %s %s\n", p.Grey("Config:"), p.Magenta(viper.ConfigFileUsed()))

	if len(cLogFiles) < 1 {
		fmt.Printf("%s No log files specified!\n", p.Red("\U00002717"))
		os.Exit(1)
	}

	s := spinner.New(spinner.CharSets[11], 200*time.Millisecond)

	// Read log file
	fmt.Printf("\U00002139 %s\n", p.Grey("Log files:"))

	for _, file := range cLogFiles {
		fmt.Printf("  \U000021C1 %s\n", p.Magenta(file))
	}

	s.Suffix = p.Grey(" Read log files")
	s.Start()
	lines, err := p.ReadLogFiles(cLogFiles)
	// time.Sleep(10 * time.Second)
	s.Stop()

	if err != nil {
		fmt.Printf("%s Reading log files failed: %s\n", p.Red("\U00002717"), p.Red(err))
		os.Exit(1)
	} else {
		msg := p.Green("\U00002714") + p.Grey(" Read log files (") + p.Teal(len(lines)) + p.Grey(" lines)")
		fmt.Println(msg)
	}

	// Parse line by line
	s.Suffix = p.Grey(" Parse logs")
	s.Start()
	parsedLogMap, err := p.Parse(lines)
	s.Stop()

	if err != nil {
		fmt.Printf("%s Parsing logs failed: %s\n", p.Red("\U00002717"), p.Red(err))
		os.Exit(1)
	} else {
		msg := p.Green("\U00002714") + p.Grey(" Parse logs (") + p.Teal(len(parsedLogMap)) + p.Grey(" entries)")
		fmt.Println(msg)
	}

	// pp.Print(parsedLogMap)

	// Populate users map
	s.Suffix = p.Grey(" Populate users map")
	s.Start()
	usersMap, err := p.PopulateUsers(parsedLogMap)
	s.Stop()

	if err != nil {
		fmt.Printf("%s Populating users map: %s\n", p.Red("\U00002717"), p.Red(err))
		os.Exit(1)
	} else {
		msg := p.Green("\U00002714") + p.Grey(" Populate users map (") + p.Teal(len(usersMap)) + p.Grey(" users)")
		fmt.Println(msg)
	}

	// pp.Print(usersMap)

	if len(usersMap) > 0 {

		if aOutputFormat == "table" {
			t := table.NewWriter()
			t.SetOutputMirror(os.Stdout)
			t.AppendHeader(table.Row{"Username", "IP Address", "Auth Method", "Version", "Software"})
			for user, el := range usersMap {
				t.AppendRow(table.Row{user, strings.Join(el.RemoteIPs, "\n"), strings.Join(el.AuthMethods, "\n"), strings.Join(el.RemoteProtocolVersions, "\n"), strings.Join(el.RemoteSoftwareVersions, "\n")})
			}
			t.AppendFooter(table.Row{"Count", len(usersMap)})
			t.SetStyle(table.StyleColoredBlackOnGreenWhite)
			t.Render()

			os.Exit(0)
		}

		if aOutputFormat == "json-file" {
			jsonStr, err := json.MarshalIndent(usersMap, "", "  ")

			if err != nil {
				fmt.Printf("%s Forming json failed: %s\n", p.Red("\U00002717"), p.Red(err))
				os.Exit(1)
			}

			// Write to file
			s.Suffix = p.Grey(" Write output to %s", cOutputJsonFile)
			s.Start()

			err = ioutil.WriteFile(cOutputJsonFile, jsonStr, 0644)
			if err != nil {
				fmt.Printf("%s Writing to %s failed: %s\n", p.Red("\U00002717"), p.Yellow(cOutputJsonFile), p.Red(err))
				os.Exit(1)
			} else {
				msg := p.Green("\U00002714") + p.Grey(" Write output to ") + p.Yellow(cOutputJsonFile)
				fmt.Println(msg)
			}

			s.Stop()

			os.Exit(0)
		}

		fmt.Printf("\nUsers:\n\n")

		for user, el := range usersMap {
			fmt.Printf(" \U0001FBC5 %s\n", p.Yellow(user))

			if (aPrintRemoteIPs || aPrintAll) && len(el.RemoteIPs) > 0 {
				fmt.Println(p.KeyText("    IP addresses:"))
				for _, ip := range el.RemoteIPs {
					fmt.Printf("    \U000021C1 %s\n", ip)
				}
				fmt.Println()
			}

			if (aPrintFailedLogins || aPrintAll) && len(el.FailedLoginsFrom) > 0 {
				fmt.Println(p.KeyText("    Failed login from:"))
				for _, ip := range el.FailedLoginsFrom {
					fmt.Printf("    \U000021C1 %s\n", ip)
				}
				fmt.Println()
			}

			if (aPrintKexClientServerCiphers || aPrintAll) && len(el.KexClientServerCiphers) > 0 {
				fmt.Println(p.KeyText("    Client ciphers:"))
				for _, c := range el.KexClientServerCiphers {
					fmt.Printf("    \U000021C1 %s\n", c)
				}
				fmt.Println()
			}

			if (aPrintKexServerClientCiphers || aPrintAll) && len(el.KexServerClientCiphers) > 0 {
				fmt.Println(p.KeyText("    Server ciphers:"))
				for _, c := range el.KexServerClientCiphers {
					fmt.Printf("    \U000021C1 %s\n", c)
				}
				fmt.Println()
			}

		}

		fmt.Printf(p.KeyText("\nUsers count: %s\n\n"), p.Green(len(usersMap)))

	} else {
		fmt.Printf("%s No users found!\n", p.Warn("\U000026A0"))

	}

}
