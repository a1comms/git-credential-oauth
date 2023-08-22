// Copyright 2022 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strings"
	"time"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/authhandler"
	"golang.org/x/oauth2/endpoints"
)

const APP = "git-credential-oauth"

type CredentialStorage struct {
	Credentials  map[string]*oauth2.Token
	LastModified time.Time
}

var credentialstore *CredentialStorage

// configByHost lists default config for several public hosts.
var configByHost = map[string]oauth2.Config{
	// https://github.com/organizations/a1comms/settings/apps/git-credentials-oauth
	"github.com": {
		ClientID: "Iv1.667f659032baad48",
		// IMPORTANT: The client "secret" below is non confidential.
		// This is expected for OAuth native apps which (unlike web apps) are public clients
		// "incapable of maintaining the confidentiality of their credentials"
		// "It is assumed that any client authentication credentials included in the application can be extracted"
		// https://datatracker.ietf.org/doc/html/rfc6749#section-2.1
		ClientSecret: "836d11be22dcaf39574fd7ee5009e4d0f1c972e7",
		Endpoint:     endpoints.GitHub,
		Scopes:       []string{},
	},
	// https://gitlab.com/oauth/applications/232663
	"gitlab.com": {
		ClientID: "10bfbbf46e5b760b55ce772a262d7a0205eacc417816eb84d37d0fb02c89bb97",
		Endpoint: endpoints.GitLab,
		Scopes:   []string{"read_repository", "write_repository"}},
	// https://gitlab.freedesktop.org/oauth/applications/68
	"gitlab.freedesktop.org": {
		ClientID: "ba28f287f465c03c629941bca9de965923c561f8e967ce02673a0cd937a94b6f",
		Endpoint: replaceHost(endpoints.GitLab, "gitlab.freedesktop.org"),
		Scopes:   []string{"read_repository", "write_repository"}},
	// https://gitlab.gnome.org/oauth/applications/112
	"gitlab.gnome.org": {
		ClientID: "9719f147e6117ef0ee9954516bd7fe292176343a7fd24a8bcd5a686e8ef1ec71",
		Endpoint: replaceHost(endpoints.GitLab, "gitlab.gnome.org"),
		Scopes:   []string{"read_repository", "write_repository"}},
	// https://code.videolan.org/oauth/applications/109
	"code.videolan.org": {
		ClientID: "a6d235d8ebc7a7eacc52be6dba0b5bc31a6d013be85e2d15f0fc9006b4c6e9ff",
		Endpoint: replaceHost(endpoints.GitLab, "code.videolan.org"),
		Scopes:   []string{"read_repository", "write_repository"}},
	// https://salsa.debian.org/oauth/applications/95
	"salsa.debian.org": {
		ClientID: "0ae3637439058e4f261db17a001a7ec9235e1fda88b6d9221222a57c14ed830d",
		Endpoint: replaceHost(endpoints.GitLab, "salsa.debian.org"),
		Scopes:   []string{"read_repository", "write_repository"}},
	// https://gitlab.haskell.org/oauth/applications/3
	"gitlab.haskell.org": {
		ClientID: "078baa23982db8d6e179fb7da816b92e6a761268b8b35a7aa1e7ee7a3891a426",
		Endpoint: replaceHost(endpoints.GitLab, "gitlab.haskell.org"),
		Scopes:   []string{"read_repository", "write_repository"}},
	// https://gitlab.alpinelinux.org/oauth/applications/7
	"gitlab.alpinelinux.org": {
		ClientID: "6e1363d5730bd1068bc908d6eda9f4f7e72352147dbe15f441a2f9e2ce5aebee",
		Endpoint: replaceHost(endpoints.GitLab, "gitlab.alpinelinux.org"),
		Scopes:   []string{"read_repository", "write_repository"}},
	// https://gitea.com/user/settings/applications/oauth2/218
	"gitea.com": {
		ClientID: "e13f8ebc-398d-4091-9481-5a37a76b51f6",
		Endpoint: oauth2.Endpoint{AuthURL: "https://gitea.com/login/oauth/authorize", TokenURL: "https://gitea.com/login/oauth/access_token"}},
	// https://codeberg.org/user/settings/applications/oauth2/223
	"codeberg.org": {
		ClientID:     "246ca3e8-e974-430c-b9ec-3d4e2b54ad28",
		ClientSecret: "gto_4stsgpwkgtsvayljdsg3xq33l2v3v245rlc45tnpt4cjp7eyw5gq",
		Endpoint:     oauth2.Endpoint{AuthURL: "https://codeberg.org/login/oauth/authorize", TokenURL: "https://codeberg.org/login/oauth/access_token"}},
	// https://bitbucket.org/a1commsltd/workspace/settings/oauth-consumers/1013298/edit
	"bitbucket.org": {
		ClientID:     "UMfcbYmgnHRcW2M4ag",
		ClientSecret: "cpc2wSgQSqBW7jUAddEcjqyXxzAgZDfe",
		Endpoint:     endpoints.Bitbucket,
		Scopes:       []string{"repository", "repository:write"}},
	// https://bitbucket.org/a1commsltd/workspace/settings/oauth-consumers/1012852/edit
	"bitbucket.org-headless": {
		ClientID:     "Qz4LBMfmLAHGnDgNAY",
		ClientSecret: "fCJ9c6FDQ8pwQrT4nShF6USjxVEzypcy",
		RedirectURL:  "https://git-oauth2.a1comms.net/bitbucket/",
		Endpoint:     endpoints.Bitbucket,
		Scopes:       []string{"repository", "repository:write"}},
	"android.googlesource.com": {
		ClientID:     "897755559425-di05p489vpt7iv09thbf5a1ombcbs5v0.apps.googleusercontent.com",
		ClientSecret: "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",
		Endpoint:     endpoints.Google,
		Scopes:       []string{"https://www.googleapis.com/auth/gerritcodereview"}},
}

var (
	verbose bool
	// populated by GoReleaser https://goreleaser.com/cookbooks/using-main.version
	version = "dev"
)

func printVersion() {
	info, ok := debug.ReadBuildInfo()
	if ok && version == "dev" {
		version = info.Main.Version
	}
	if verbose {
		fmt.Fprintf(os.Stderr, "git-credential-oauth %s\n", version)
	}
}

func parse(input string) map[string]string {
	lines := strings.Split(string(input), "\n")
	pairs := map[string]string{}
	for _, line := range lines {
		parts := strings.SplitN(line, "=", 2)
		if len(parts) >= 2 {
			pairs[parts[0]] = parts[1]
		}
	}
	return pairs
}

func main() {
	flag.BoolVar(&verbose, "verbose", false, "log debug information to stderr")
	flag.Usage = func() {
		printVersion()
		fmt.Fprintln(os.Stderr, "usage: git credential-oauth [<options>] <action>")
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "Options:")
		flag.PrintDefaults()
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "Actions:")
		fmt.Fprintln(os.Stderr, "  get                    Generate credential")
		fmt.Fprintln(os.Stderr, "  refresh bitbucket      Configure BitBucket credentials")
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "See also https://github.com/a1comms/git-credential-oauth")
	}
	flag.Parse()
	args := flag.Args()
	if len(args) < 1 {
		flag.Usage()
		os.Exit(2)
	}

	err := LoadCredentialStorage()
	if err != nil {
		panic(err)
	}
	defer func() {
		err := SaveCredentialStorage()
		if err != nil {
			panic(err)
		}
	}()

	switch args[0] {
	case "get":
		printVersion()
		input, err := io.ReadAll(os.Stdin)
		if err != nil {
			log.Fatalln(err)
		}
		pairs := parse(string(input))
		if verbose {
			fmt.Fprintln(os.Stderr, "input:", pairs)
		}
		host := pairs["host"]
		if host == "gist.github.com" {
			host = "github.com"
		}
		looksLikeGitLab := strings.HasPrefix(host, "gitlab.") || strings.Contains(pairs["wwwauth[]"], `Realm="GitLab"`)
		urll := fmt.Sprintf("%s://%s", pairs["protocol"], host)
		c, found := configByHost[host]
		if !found && strings.HasSuffix(host, ".googlesource.com") {
			c = configByHost["android.googlesource.com"]
		}
		if !found && looksLikeGitLab {
			// TODO: universal GitLab support with constant client id
			// https://gitlab.com/gitlab-org/gitlab/-/issues/374172
			// c.ClientID = ...

			// assumes GitLab installed at domain root
			c.Endpoint = replaceHost(endpoints.GitLab, host)
			c.Scopes = configByHost["gitlab.com"].Scopes
		}
		gitPath, err := exec.LookPath("git")
		if err == nil {
			cmd := exec.Command(gitPath, "config", "--get-urlmatch", "credential.oauthClientId", urll)
			bytes, err := cmd.Output()
			if err == nil {
				c.ClientID = strings.TrimSpace(string(bytes))
			}
			bytes, err = exec.Command(gitPath, "config", "--get-urlmatch", "credential.oauthClientSecret", urll).Output()
			if err == nil {
				c.ClientSecret = strings.TrimSpace(string(bytes))
			}
			bytes, err = exec.Command(gitPath, "config", "--get-urlmatch", "credential.oauthScopes", urll).Output()
			if err == nil {
				c.Scopes = []string{strings.TrimSpace(string(bytes))}
			}
			bytes, err = exec.Command(gitPath, "config", "--get-urlmatch", "credential.oauthAuthURL", urll).Output()
			if err == nil {
				c.Endpoint.AuthURL, err = urlResolveReference(urll, strings.TrimSpace(string(bytes)))
				if err != nil {
					log.Fatalln(err)
				}
			}
			bytes, err = exec.Command(gitPath, "config", "--get-urlmatch", "credential.oauthTokenURL", urll).Output()
			if err == nil {
				c.Endpoint.TokenURL, err = urlResolveReference(urll, strings.TrimSpace(string(bytes)))
				if err != nil {
					log.Fatalln(err)
				}
			}
			bytes, err = exec.Command(gitPath, "config", "--get-urlmatch", "credential.oauthRedirectURL", urll).Output()
			if err == nil {
				c.RedirectURL = strings.TrimSpace(string(bytes))
			}
		}
		if c.ClientID == "" || c.Endpoint.AuthURL == "" || c.Endpoint.TokenURL == "" {
			if looksLikeGitLab {
				fmt.Fprintf(os.Stderr, "\nIt looks like you're authenticating to a GitLab instance! To configure git-credential-oauth for host %s, follow the instructions at https://github.com/hickford/git-credential-oauth/issues/18. You may need to register an OAuth application at https://%s/-/profile/applications\n", host, host)
			}
			return
		}

		if host == "github.com" {
			fmt.Fprintf(os.Stderr, "\nUsing GitHub App authentication - if you get a 403, install the app by visiting:\n\nhttps://github.com/apps/git-credentials-oauth/installations/new\n\n")
		}

		token, err := fetchToken(host, urll, c)
		if err != nil {
			fmt.Fprintln(os.Stderr, "\nERROR: %s\n", err)
			fmt.Printf("%s=%s\n", "quit", "true")
			os.Exit(2)
		}

		var username string
		if host == "bitbucket.org" {
			// https://support.atlassian.com/bitbucket-cloud/docs/use-oauth-on-bitbucket-cloud/#Cloning-a-repository-with-an-access-token
			username = "x-token-auth"
		} else if looksLikeGitLab {
			// https://docs.gitlab.com/ee/api/oauth2.html#access-git-over-https-with-access-token
			username = "oauth2"
		} else if pairs["username"] == "" {
			username = "oauth2"
		}
		output := map[string]string{
			"password": token.AccessToken,
		}
		if username != "" {
			output["username"] = username
		}
		if verbose {
			fmt.Fprintln(os.Stderr, "output:", output)
		}
		for key, v := range output {
			fmt.Printf("%s=%s\n", key, v)
		}
	case "refresh":
		if len(args) != 2 {
			flag.Usage()
			os.Exit(2)
		}

		var (
			c     oauth2.Config
			found bool
			host  string
			urll  string
			err   error
		)

		switch args[1] {
		case "bitbucket":
			c, found = configByHost["bitbucket.org"]
			if !found {
				fmt.Fprintln(os.Stderr, "ERROR: Configuration for BitBucket not found")
				os.Exit(2)
			}
			host, urll = "bitbucket.org", "https://bitbucket.org"
		default:
			flag.Usage()
			os.Exit(2)
		}

		_, err = fetchToken(host, urll, c)
		if err != nil {
			fmt.Fprintln(os.Stderr, "\nERROR: %s\n", err)
			os.Exit(2)
		}

		fmt.Fprintln(os.Stderr, "Successfully refreshed token")
	}
}

var (
	ErrHeadless = errors.New("can't open URL, running headless")
)

func getToken(c oauth2.Config) (*oauth2.Token, error) {
	state := randomString(16)
	queries := make(chan url.Values)
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// TODO: consider whether to show errors in browser or command line
		queries <- r.URL.Query()
		w.Write([]byte("Success. You may close this page and return to Git."))
	})
	var server *httptest.Server
	if c.RedirectURL == "" {
		server = httptest.NewServer(handler)
		c.RedirectURL = server.URL
	} else {
		server = httptest.NewUnstartedServer(handler)
		url, err := url.Parse(c.RedirectURL)
		if err != nil {
			log.Fatalln(err)
		}
		l, err := net.Listen("tcp", url.Host)
		if err != nil {
			log.Fatalln(err)
		}
		server.Listener = l
		server.Start()
	}
	defer server.Close()

	token, err := authhandler.TokenSourceWithPKCE(context.Background(), &c, state, func(authCodeURL string) (code string, state string, err error) {
		defer server.Close()

		var open string
		switch runtime.GOOS {
		case "windows":
			open = "start"
		case "darwin":
			open = "open"
		default:
			open = "xdg-open"
		}
		// TODO: wait for server to start before opening browser
		if _, err := exec.LookPath(open); err == nil {
			err = exec.Command(open, authCodeURL).Run()
			if err != nil {
				fmt.Fprintf(os.Stderr, "\nFailed to automatically open authentication URL in your browser: %s\n", err)
				return "", "", ErrHeadless
			}
			fmt.Fprintf(os.Stderr, "\nPlease complete authentication in your browser...\n\n%s\n", authCodeURL)
		} else {
			return "", "", ErrHeadless
		}
		query := <-queries
		if verbose {
			fmt.Fprintln(os.Stderr, "query:", query)
		}
		return query.Get("code"), query.Get("state"), nil
	}, generatePKCEParams()).Token()
	if err == ErrHeadless {
		return getDeviceToken(c)
	} else {
		return token, err
	}
}

type AuthResponse struct {
	Code  string `json:"code"`
	State string `json:"state"`
}

func getDeviceToken(c oauth2.Config) (*oauth2.Token, error) {
	if c.Endpoint.DeviceAuthURL == "" {
		if c.Endpoint.AuthURL == endpoints.Bitbucket.AuthURL {
			stat, _ := os.Stdin.Stat()
			if (stat.Mode() & os.ModeCharDevice) == 0 {
				fmt.Fprintf(os.Stderr, "\nTo continue, please run the command: git credential-oauth refresh bitbucket\n\n")
				fmt.Printf("%s=%s\n", "quit", "true")
				os.Exit(2)
			}

			state := randomString(16)
			var found bool
			c, found = configByHost["bitbucket.org-headless"]
			if !found {
				return nil, fmt.Errorf("Configuration for BitBucket not found")
			}
			return authhandler.TokenSourceWithPKCE(context.Background(), &c, state, func(authCodeURL string) (code string, state string, err error) {
				fmt.Fprintf(os.Stderr, "Please complete authentication in your browser...\n\n%s\n\n", authCodeURL)

				fmt.Fprintf(os.Stderr, "Paste your response token here: ")
				input := bufio.NewScanner(os.Stdin)
				input.Scan()

				authResponseToken, err := base64.StdEncoding.DecodeString(input.Text())
				if err != nil {
					return "", "", err
				}

				authResponse := &AuthResponse{}

				err = json.Unmarshal(authResponseToken, authResponse)
				if err != nil {
					return "", "", err
				}

				return authResponse.Code, authResponse.State, nil
			}, generatePKCEParams()).Token()
		} else {
			fmt.Fprintln(os.Stderr, "host doesn't support device auth")
			os.Exit(0)
		}
	}
	deviceAuth, err := c.DeviceAuth(context.Background())
	if err != nil {
		log.Fatalln(err)
	}
	if verbose {
		fmt.Fprintln(os.Stderr, deviceAuth)
	}
	fmt.Fprintf(os.Stderr, "Please enter code %s at %s\n", deviceAuth.UserCode, deviceAuth.VerificationURI)
	return c.DeviceAccessToken(context.Background(), deviceAuth)
}

func fetchToken(host, urll string, c oauth2.Config) (*oauth2.Token, error) {
	var (
		err   error
		token *oauth2.Token
	)

	if tok, ok := credentialstore.Credentials[urll]; ok {
		if verbose {
			fmt.Fprintln(os.Stderr, "refreshing token...")
		}
		token, err = oauth2.ReuseTokenSourceWithExpiry(
			tok,
			c.TokenSource(context.Background(), tok),
			time.Minute*10,
		).Token()
		if err != nil {
			if host == "bitbucket.org" {
				var found bool

				c, found = configByHost["bitbucket.org-headless"]
				if !found {
					return nil, fmt.Errorf("Configuration for BitBucket not found")
				}

				token, err = oauth2.ReuseTokenSourceWithExpiry(
					tok,
					c.TokenSource(context.Background(), tok),
					time.Minute*10,
				).Token()
			}
			if err != nil {
				fmt.Errorf("error during OAuth token refresh: %s", err)
			}
		}
	}

	if token == nil {
		// Generate new token
		token, err = getToken(c)
		if err != nil {
			return nil, err
		}
	}

	if verbose {
		fmt.Fprintln(os.Stderr, "token: ", token)
	}

	credentialstore.Credentials[urll] = token

	return token, nil
}

func randomString(n int) string {
	data := make([]byte, n)
	if _, err := io.ReadFull(rand.Reader, data); err != nil {
		panic(err)
	}
	return base64.StdEncoding.EncodeToString(data)
}

func replaceHost(e oauth2.Endpoint, host string) oauth2.Endpoint {
	url, err := url.Parse(e.AuthURL)
	if err != nil {
		panic(err)
	}
	e.AuthURL = strings.Replace(e.AuthURL, url.Host, host, 1)
	e.TokenURL = strings.Replace(e.TokenURL, url.Host, host, 1)
	return e
}

func generatePKCEParams() *authhandler.PKCEParams {
	verifier := randomString(32)
	sha := sha256.Sum256([]byte(verifier))
	challenge := base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(sha[:])

	return &authhandler.PKCEParams{
		Challenge:       challenge,
		ChallengeMethod: "S256",
		Verifier:        verifier,
	}
}

func urlResolveReference(base, ref string) (string, error) {
	base1, err := url.Parse(base)
	if err != nil {
		return "", err
	}
	ref1, err := url.Parse(ref)
	if err != nil {
		return "", err
	}
	return base1.ResolveReference(ref1).String(), nil
}

func LoadCredentialStorage() error {
	file, err := GetCredentialStorageFile()
	if err != nil {
		return err
	}
	defer file.Close()

	dec := json.NewDecoder(file)

	err = dec.Decode(&credentialstore)
	if err == io.EOF {
		credentialstore = &CredentialStorage{
			Credentials: make(map[string]*oauth2.Token),
		}
		return nil
	}
	return err
}

func SaveCredentialStorage() error {
	file, err := GetCredentialStorageFile()
	if err != nil {
		return err
	}
	defer file.Close()

	enc := json.NewEncoder(file)
	enc.SetIndent("", "    ")

	credentialstore.LastModified = time.Now()

	return enc.Encode(credentialstore)
}

func GetCredentialStorageFile() (*os.File, error) {
	location := GetRuntimeSpecificConfigDirectory()

	if _, err := os.Stat(location); os.IsNotExist(err) {
		if err = os.MkdirAll(location, 0700); err != nil {
			return nil, err
		}
	}

	location = filepath.Join(location, "credentials.json")

	return os.OpenFile(location, os.O_RDWR|os.O_CREATE, 0600)
}

func GetRuntimeSpecificConfigDirectory() string {
	var homeDir string
	usr, err := user.Current()
	if err == nil {
		homeDir = usr.HomeDir
	}

	// Fall back to standard HOME environment variable that works
	// for most POSIX OSes if the directory from the Go standard
	// lib failed.
	if err != nil || homeDir == "" {
		homeDir = os.Getenv("HOME")
	}

	switch runtime.GOOS {
	case "windows":
		return filepath.Join(GetEnvAsString("LOCALAPPDATA", os.Getenv("APPDATA")), APP)
	case "darwin":
		return filepath.Join(homeDir, "Library", "Application Support", APP)
	default:
		return filepath.Join(GetEnvAsString("XDG_DATA_HOME", filepath.Join(GetEnvAsString("HOME", "."), ".local", "share")), APP)
	}
}

func GetEnvAsString(name, fallback string) string {
	if value, ok := os.LookupEnv(name); ok && len(value) > 0 {
		return value
	}
	return fallback
}
