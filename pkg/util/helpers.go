package util

import (
	"bufio"
	"fmt"
	"github.com/fatih/color"
	"io/ioutil"
	"os"
	"os/exec"
	"regexp"
	"strings"
)

var aliases []string
var results []map[string]bool

func isStringInArray(target string, array []string) bool {
	for _, element := range array {
		if element == target {
			return true
		}
	}
	return false
}

func IsAliasInConfigFile(configFile string) []string {
	data, err := ioutil.ReadFile(configFile)
	if err != nil {
		color.Red("Error reading file:", err)
		return nil
	}

	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		// Skip comment lines and empty lines
		if strings.HasPrefix(strings.TrimSpace(line), "#") || len(line) == 0 {
			continue
		}

		parts := strings.Split(line, "=")
		if len(parts) >= 2 {
			parts2 := parts[0]
			part := strings.Split(parts2, " ")
			if len(part) == 2 && part[0] == "alias" {
				aliases = append(aliases, part[1])

			}
		}
	}

	return aliases
}

// Function to check if a command is valid without running it
func isValidCommand(command string) bool {

	if isStringInArray(command, aliases) {
		return true
	}

	if command == "cd" || command == "export" || command == "history" || command == "source" {
		return true
	}

	cmd := exec.Command("which", command)
	err := cmd.Run()

	if err == nil {
		return true
	}

	cmd = exec.Command("bash", "-n", "-c", command)
	err2 := cmd.Run()

	_, err3 := exec.LookPath(command)

	if err2 != nil || err3 != nil {

		return false
	}
	return err2 == nil && err3 == nil
}

func extractSecretPassword(input string) (string, error) {
	// Check if the string starts with ":" and contains ";"
	if !strings.HasPrefix(input, ":") || !strings.Contains(input, ";") {
		return "", fmt.Errorf("invalid input format")
	}

	// Extract the substring after ";"
	password := strings.SplitN(input, ";", 2)[1]

	passwordParts := strings.Fields(password)
	if len(passwordParts) == 0 {
		return "", fmt.Errorf("no password found")
	}

	return passwordParts[0], nil
}

func extractSecretPasswordRegex(input string) (string, error) {
	// Check if the string starts with ":" and contains ";"
	if !strings.HasPrefix(input, ":") || !strings.Contains(input, ";") {
		return "", fmt.Errorf("invalid input format")
	}

	// Extract the substring after ";"
	password := strings.SplitN(input, ";", 2)[1]

	return password, nil
}

func ProcessZshHistoryFile(historyFile string) {
	// Open the zsh history file
	f, err := os.Open(historyFile)
	if err != nil {
		color.Red("Error opening zsh history file %s: %v\n", historyFile, err)
		return
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	var currentCommand string

	// Read each line from the zsh history file
	for scanner.Scan() {
		line := scanner.Text()
		line = strings.TrimSpace(line)

		if strings.HasPrefix(line, ":") {
			// New command starts with ":" - Save it as the current command
			currentCommand, _ = extractSecretPassword(line)

		} else {
			// Command line doesn't match the expected format, skip
			continue
		}

		if strings.HasSuffix(currentCommand, "\\") {
			// Command continues to the next line, remove the line continuation marker
			currentCommand = strings.TrimSuffix(currentCommand, "\\")
			continue
		}

		// Process the completed command
		if !isValidCommand(currentCommand) {
			color.Yellow("Invalid command in %s: %s\n", historyFile, currentCommand)
		}

		// Reset the current command
		currentCommand = ""
	}

	if err := scanner.Err(); err != nil {
		color.Red("Error reading zsh history file %s: %v\n", historyFile, err)
	}
}

func ProcessBashHistoryFile(historyFile string) {
	// Open the bash history file
	f, err := os.Open(historyFile)
	if err != nil {
		color.Red("Error opening bash history file %s: %v\n", historyFile, err)
		return
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)

	// Read each line from the bash history file
	for scanner.Scan() {
		command := scanner.Text()
		parts := strings.Split(command, " ")

		// Process the command
		if !isValidCommand(parts[0]) {
			color.Red("Invalid command in %s: %s\n", historyFile, command)
		}
	}

	if err := scanner.Err(); err != nil {
		color.Red("Error reading bash history file %s: %v\n", historyFile, err)
	}
}

func ProcessBashHistoryFileRegex(historyFile string) {
	// Open the bash history file
	f, err := os.Open(historyFile)
	if err != nil {
		color.Red("Error opening bash history file %s: %v\n", historyFile, err)
		return
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)

	// Read each line from the bash history file
	for scanner.Scan() {
		command := scanner.Text()

		results = append(results, DetectRegexes(command))

	}

	if err := scanner.Err(); err != nil {
		color.Red("Error reading bash history file %s: %v\n", historyFile, err)
	}
}
func ProcessZshHistoryFileRegex(historyFile string) {
	// Open the zsh history file
	f, err := os.Open(historyFile)
	if err != nil {
		color.Red("Error opening zsh history file %s: %v\n", historyFile, err)
		return
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	var currentCommand string

	// Read each line from the zsh history file
	for scanner.Scan() {
		line := scanner.Text()
		line = strings.TrimSpace(line)

		if strings.HasPrefix(line, ":") {
			// New command starts with ":" - Save it as the current command
			currentCommand, _ = extractSecretPasswordRegex(line)

		} else {
			// Command line doesn't match the expected format, skip
			continue
		}

		if strings.HasSuffix(currentCommand, "\\") {
			// Command continues to the next line, remove the line continuation marker
			currentCommand = strings.TrimSuffix(currentCommand, "\\")
			continue
		}

		// Process the completed command
		results = append(results, DetectRegexes(currentCommand))

		// Reset the current command
		currentCommand = ""
	}

	if err := scanner.Err(); err != nil {
		color.Red("Error reading zsh history file %s: %v\n", historyFile, err)
	}
}
func DetectRegexes(input string) map[string]bool {
	regexes := map[string]string{
		"Cloudinary":                    "cloudinary://.*",
		"Firebase URL":                  ".*firebaseio\\.com",
		"Slack Token":                   "(xox[p|b|o|a]-[0-9]{12}-[0-9]{12}-[0-9]{12}-[a-z0-9]{32})",
		"RSA private key":               "-----BEGIN RSA PRIVATE KEY-----",
		"SSH (DSA) private key":         "-----BEGIN DSA PRIVATE KEY-----",
		"SSH (EC) private key":          "-----BEGIN EC PRIVATE KEY-----",
		"PGP private key block":         "-----BEGIN PGP PRIVATE KEY BLOCK-----",
		"Amazon AWS Access Key ID":      "AKIA[0-9A-Z]{16}",
		"Amazon MWS Auth Token":         "amzn\\.mws\\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
		"AWS API Key":                   "AKIA[0-9A-Z]{16}",
		"Facebook Access Token":         "EAACEdEose0cBA[0-9A-Za-z]+",
		"Facebook OAuth":                "[f|F][a|A][c|C][e|E][b|B][o|O][o|O][k|K].*['|\"][0-9a-f]{32}['|\"]",
		"GitHub":                        "[g|G][i|I][t|T][h|H][u|U][b|B].*['|\"][0-9a-zA-Z]{35,40}['|\"]",
		"Generic API Key":               "[a|A][p|P][i|I][_]?[k|K][e|E][y|Y].*['|\"][0-9a-zA-Z]{32,45}['|\"]",
		"Generic Secret":                "[s|S][e|E][c|C][r|R][e|E][t|T].*['|\"][0-9a-zA-Z]{32,45}['|\"]",
		"Google API Key":                "AIza[0-9A-Za-z\\-_]{35}",
		"Google Cloud Platform API Key": "AIza[0-9A-Za-z\\-_]{35}",
		"Google Cloud Platform OAuth":   "[0-9]+-[0-9A-Za-z_]{32}\\.apps\\.googleusercontent\\.com",
		"Google Drive API Key":          "AIza[0-9A-Za-z\\-_]{35}",
		"Google Drive OAuth":            "[0-9]+-[0-9A-Za-z_]{32}\\.apps\\.googleusercontent\\.com",
		"Google (GCP) Service-account":  "\"type\": \"service_account\"",
		"Google Gmail API Key":          "AIza[0-9A-Za-z\\-_]{35}",
		"Google Gmail OAuth":            "[0-9]+-[0-9A-Za-z_]{32}\\.apps\\.googleusercontent\\.com",
		"Google OAuth Access Token":     "ya29\\.[0-9A-Za-z\\-_]+",
		"Google YouTube API Key":        "AIza[0-9A-Za-z\\-_]{35}",
		"Google YouTube OAuth":          "[0-9]+-[0-9A-Za-z_]{32}\\.apps\\.googleusercontent\\.com",
		"Heroku API Key":                "[h|H][e|E][r|R][o|O][k|K][u|U].*[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}",
		"MailChimp API Key":             "[0-9a-f]{32}-us[0-9]{1,2}",
		"Mailgun API Key":               "key-[0-9a-zA-Z]{32}",
		"Password in URL":               "[a-zA-Z]{3,10}://[^/\\s:@]{3,20}:[^/\\s:@]{3,20}@.{1,100}[\"'\\s]",
		"PayPal Braintree Access Token": "access_token\\$production\\$[0-9a-z]{16}\\$[0-9a-f]{32}",
		"Picatic API Key":               "sk_live_[0-9a-z]{32}",
		"Slack Webhook":                 "https://hooks.slack.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8}/[a-zA-Z0-9_]{24}",
		"Stripe API Key":                "sk_live_[0-9a-zA-Z]{24}",
		"Stripe Restricted API Key":     "rk_live_[0-9a-zA-Z]{24}",
		"Square Access Token":           "sq0atp-[0-9A-Za-z\\-_]{22}",
		"Square OAuth Secret":           "sq0csp-[0-9A-Za-z\\-_]{43}",
		"Twilio API Key":                "SK[0-9a-fA-F]{32}",
		"Twitter Access Token":          "[t|T][w|W][i|I][t|T][t|T][e|E][r|R].*[1-9][0-9]+-[0-9a-zA-Z]{40}",
		"Twitter OAuth":                 "[t|T][w|W][i|I][t|T][t|T][e|E][r|R].*['|\"][0-9a-zA-Z]{35,44}['|\"]",
	}

	results := make(map[string]bool)

	for label, regex := range regexes {
		match, err := regexp.MatchString(regex, input)
		if err != nil {
			color.Red("Error evaluating regex for '%s': %v\n", label, err)
			continue
		}
		results[label] = match

		if match {
			color.Green(label)
			color.Red(input)
		}
	}

	return results
}
