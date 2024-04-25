/*
Copyright © 2023 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"os"

	"github.com/spf13/cobra"
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "PassDetective",
	Short: "Extract passwords from shell history change descriptions",
	Long: `The "extract" command allows you to automatically extract passwords from shell history change descriptions.
By analyzing the history of shell commands, this tool can identify and extract passwords that were used during
previous commands and display them for further inspection or use.
`,
	// Uncomment the following line if your bare application
	// has an action associated with it:
	Run: func(cmd *cobra.Command, args []string) {
		cmd.Println("__________                     ________           __                  __   __              \n\\______   \\____    ______ ____________ \\   ____ _/  |_  ____   ____ _/  |_|__|__  __ ____  \n |     ___/__  \\  /  ___//  ___/|    |  \\_/ __ \\\\   __\\/ __ \\_/ ___\\\\   __\\  |  \\/ // __ \\ \n |    |    / __ \\_\\___ \\ \\___ \\ |    |   \\  ___/_|  | \\  ___/_  \\___ |  | |  |\\   /\\  ___/_\n |____|   (____  /____  \\____  \\_______  /\\___  /|__|  \\___  /\\___  /|__| |__| \\_/  \\___  /\n               \\/     \\/     \\/        \\/     \\/           \\/     \\/                    \\/ \n")
		cmd.Help()

	},
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func init() {
	// Here you will define your flags and configuration settings.
	// Cobra supports persistent flags, which, if defined here,
	// will be global for your application.

	// rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.main.go.yaml)")

	// Cobra also supports local flags, which will only run
	// when this action is called directly.
	rootCmd.Flags().BoolP("help", "h", false, "Help message for PassDetective")

}
