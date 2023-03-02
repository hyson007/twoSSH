package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/terminal"
)

func main() {
	var (
		sshAddr1  string
		sshAddr2  string
		sshKey1   string
		sshKey2   string
		command1  string
		command2  string
		username1 string
		username2 string
		output1   chan string
		output2   chan string
		err1      error
		err2      error
		session1  *ssh.Session
		session2  *ssh.Session
		client1   *ssh.Client
		client2   *ssh.Client
		// config1   *ssh.ClientConfig
		// config2   *ssh.ClientConfig
		// hostKey   ssh.PublicKey
		startTime time.Time
	)

	var rootCmd = &cobra.Command{
		Use:   "ssh-exec",
		Short: "Executes commands over SSH",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Println("Starting SSH commands...")
			startTime = time.Now()

			config1, err := newClientConfig(username1, sshKey1)
			if err != nil {
				log.Panic("unable to create client config", err)
			}
			config2, err := newClientConfig(username2, sshKey2)
			if err != nil {
				log.Panic("unable to create client config", err)
			}
			client1, err1 = ssh.Dial("tcp", sshAddr1, config1)
			if err1 != nil {
				log.Println(sshAddr1)
				panic(err1)
			}
			client2, err2 = ssh.Dial("tcp", sshAddr2, config2)
			if err2 != nil {
				log.Println(sshAddr2)
				panic(err2)
			}
			session1, err1 = client1.NewSession()
			if err1 != nil {
				panic(err1)
			}
			defer session1.Close()
			session2, err2 = client2.NewSession()
			if err2 != nil {
				panic(err2)
			}
			defer session2.Close()
			output1 = make(chan string)
			output2 = make(chan string)
			go runCommand(session1, command1, output1)
			go runCommand(session2, command2, output2)
			fmt.Printf("Command 1 output:\n%s\n", <-output1)
			fmt.Printf("Command 2 output:\n%s\n", <-output2)
			fmt.Printf("Time taken: %s\n", time.Since(startTime))
		},
	}

	rootCmd.Flags().StringVarP(&sshAddr1, "address1", "a", "", "SSH server1 address")
	rootCmd.Flags().StringVarP(&sshAddr2, "address2", "b", "", "SSH server2 address")
	rootCmd.Flags().StringVarP(&sshKey1, "key1", "k", "", "SSH key file for session 1")
	rootCmd.Flags().StringVarP(&sshKey2, "key2", "j", "", "SSH key file for session 2")
	rootCmd.Flags().StringVarP(&username1, "username1", "u", "", "Username1 for session 1")
	rootCmd.Flags().StringVarP(&username2, "username2", "v", "", "Username2 for session 2")
	rootCmd.Flags().StringVarP(&command1, "command1", "c", "", "Command to execute on session 1")
	rootCmd.Flags().StringVarP(&command2, "command2", "d", "", "Command to execute on session 2")
	rootCmd.MarkFlagRequired(sshAddr1)
	rootCmd.MarkFlagRequired(sshAddr2)
	rootCmd.MarkFlagRequired(sshKey1)
	rootCmd.MarkFlagRequired(sshKey2)
	rootCmd.MarkFlagRequired(username1)
	rootCmd.MarkFlagRequired(username2)
	rootCmd.MarkFlagRequired(command1)
	rootCmd.MarkFlagRequired(command2)

	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func newClientConfig(user, keyFile string) (*ssh.ClientConfig, error) {
	privateKeyBytes, err := ioutil.ReadFile(keyFile)
	if err != nil {
		log.Println("error reading private key: ", err)
		return nil, err
	}

	// signer, err := ssh.ParsePrivateKey(privateKeyBytes)
	// if err != nil {
	// 	log.Println("error parsing private key: ", err)
	// 	return nil, err
	// }

	signer, err := ssh.ParsePrivateKeyWithPassphrase(privateKeyBytes, getPassphrase())
	if err != nil {
		log.Println("error parsing private key: ", err)
		return nil, err
	}

	auth := []ssh.AuthMethod{ssh.PublicKeys(signer)}

	return &ssh.ClientConfig{
		User:            user,
		Auth:            auth,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}, nil
}

func runCommand(session *ssh.Session, command string, output chan string) {
	log.Println("running command: ", command)
	result, err := session.CombinedOutput(command)
	if err != nil {
		log.Println("error running command: ", err)
	}
	output <- string(result)
}

func getPassphrase() []byte {
	fmt.Print("Enter passphrase for key: \n")
	bytePass, err := terminal.ReadPassword(int(syscall.Stdin))
	if err != nil {
		log.Panic("error reading passphrase", err)
	}
	return bytePass
}
