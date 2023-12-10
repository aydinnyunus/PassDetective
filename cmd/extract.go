/*
Copyright © 2023 Yunus AYDIN <aydinnyunus@gmail.com>
*/
package cmd

import (
	"github.com/fatih/color"
	"github.com/aydinnyunus/PassDetective/pkg/util"
	"os"
	"strings"

	"github.com/spf13/cobra"
)

var aliases []string

var secrets bool
var bash bool
var zsh bool
var all bool

// extractCmd represents the extract command
var extractCmd = &cobra.Command{
	Use:   "extract",
	Short: "Extract passwords from shell history",
	Long: `The "extract" command allows you to automatically extract passwords from shell history.
By analyzing the history of shell commands, this tool can identify and extract passwords that were used during
previous commands and display them for further inspection or use.
`,
	Run: func(cmd *cobra.Command, args []string) {
		zsh, _ = cmd.Flags().GetBool("zsh")
		bash, _ = cmd.Flags().GetBool("bash")
		secrets, _ = cmd.Flags().GetBool("secrets")
		all, _ = cmd.Flags().GetBool("all")

		if all {
			zsh = true
			bash = true
		}

		if zsh == false && bash == false {
			cmd.Println("__________                     ________           __                  __   __              \n\\______   \\____    ______ ____________ \\   ____ _/  |_  ____   ____ _/  |_|__|__  __ ____  \n |     ___/__  \\  /  ___//  ___/|    |  \\_/ __ \\\\   __\\/ __ \\_/ ___\\\\   __\\  |  \\/ // __ \\ \n |    |    / __ \\_\\___ \\ \\___ \\ |    |   \\  ___/_|  | \\  ___/_  \\___ |  | |  |\\   /\\  ___/_\n |____|   (____  /____  \\____  \\_______  /\\___  /|__|  \\___  /\\___  /|__| |__| \\_/  \\___  /\n               \\/     \\/     \\/        \\/     \\/           \\/     \\/                    \\/ \n")
			cmd.Help()
		}

		if secrets && zsh {
			zshHistoryFile := "~/.zsh_history"

			// Expand "~" to the user's home directory
			zshHistoryFile = strings.ReplaceAll(zshHistoryFile, "~", os.Getenv("HOME"))

			zshrc := "~/.zshrc"
			zshrcFile := strings.ReplaceAll(zshrc, "~", os.Getenv("HOME"))
			aliases = util.IsAliasInConfigFile(zshrcFile)

			// Check if the zsh history file exists and process it
			if _, err := os.Stat(zshHistoryFile); err == nil {
				color.Cyan("===============================================================")

				color.Cyan("Scan is started.")
				color.Cyan("===============================================================")

				util.ProcessZshHistoryFileRegex(zshHistoryFile)
				color.Cyan("===============================================================")

				color.Cyan("Scan is finished.")
				color.Cyan("===============================================================")

			} else {
				color.Yellow("Zsh history file not found: %s\n", zshHistoryFile)
			}
			os.Exit(0)
		} else if secrets && bash {
			bashHistoryFile := "~/.bash_history"

			// Expand "~" to the user's home directory
			bashHistoryFile = strings.ReplaceAll(bashHistoryFile, "~", os.Getenv("HOME"))

			bashrc := "~/.bashrc"
			bashrcFile := strings.ReplaceAll(bashrc, "~", os.Getenv("HOME"))
			aliases = util.IsAliasInConfigFile(bashrcFile)

			// Check if the bash history file exists and process it
			if _, err := os.Stat(bashHistoryFile); err == nil {
				color.Cyan("===============================================================")
				color.Cyan("Scan is started.")
				color.Cyan("===============================================================")
				util.ProcessBashHistoryFileRegex(bashHistoryFile)
				color.Cyan("===============================================================")
				color.Cyan("Scan is finished.")
				color.Cyan("===============================================================")

			} else {
				color.Yellow("Bash history file not found: %s\n", bashHistoryFile)
			}
			os.Exit(0)
		}
		if zsh {
			zshHistoryFile := "~/.zsh_history"

			// Expand "~" to the user's home directory
			zshHistoryFile = strings.ReplaceAll(zshHistoryFile, "~", os.Getenv("HOME"))

			zshrc := "~/.zshrc"
			zshrcFile := strings.ReplaceAll(zshrc, "~", os.Getenv("HOME"))
			aliases = util.IsAliasInConfigFile(zshrcFile)

			// Check if the zsh history file exists and process it
			if _, err := os.Stat(zshHistoryFile); err == nil {
				color.Cyan("Scan is started.")
				util.ProcessZshHistoryFile(zshHistoryFile)
				color.Cyan("Scan is finished.")

			} else {
				color.Yellow("Zsh history file not found: %s\n", zshHistoryFile)
			}

		}

		if bash {
			bashHistoryFile := "~/.bash_history"

			// Expand "~" to the user's home directory
			bashHistoryFile = strings.ReplaceAll(bashHistoryFile, "~", os.Getenv("HOME"))

			bashrc := "~/.bashrc"
			bashrcFile := strings.ReplaceAll(bashrc, "~", os.Getenv("HOME"))
			aliases = util.IsAliasInConfigFile(bashrcFile)

			// Check if the bash history file exists and process it
			if _, err := os.Stat(bashHistoryFile); err == nil {
				color.Cyan("===============================================================")

				color.Cyan("Scan is started.")
				color.Cyan("===============================================================")

				util.ProcessBashHistoryFile(bashHistoryFile)
				color.Cyan("===============================================================")

				color.Cyan("Scan is finished.")
				color.Cyan("===============================================================")

			} else {
				color.Yellow("Bash history file not found: %s\n", bashHistoryFile)
			}

		}
	},
}

func init() {
	extractCmd.Flags().BoolP("zsh", "z", false, "Check passwords on ZSH")
	extractCmd.Flags().BoolP("bash", "b", false, "Check passwords on BASH")
	extractCmd.Flags().BoolP("secrets", "s", false, "Check secrets on shell history")
	extractCmd.Flags().BoolP("all", "a", false, "Check passwords on all shells")

	rootCmd.AddCommand(extractCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// extractCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// extractCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
