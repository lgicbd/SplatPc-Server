package accounts

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"golang.org/x/term"
)

// parseMixed lets switches follow positional arguments (`add <pid> --password-stdin`).
func parseMixed(flags *flag.FlagSet, args []string) ([]string, error) {
	var positional []string
	for {
		if err := flags.Parse(args); err != nil {
			return nil, err
		}
		if flags.NArg() == 0 {
			return positional, nil
		}
		positional = append(positional, flags.Arg(0))
		args = flags.Args()[1:]
	}
}

func optionalPID(text string) (*uint32, error) {
	if text == "" {
		return nil, nil
	}
	pid, err := ParsePID(text)
	if err != nil {
		return nil, err
	}
	return &pid, nil
}

func pidColumn(pid *uint32) string {
	if pid == nil {
		return "-"
	}
	return fmt.Sprintf("%08x", *pid)
}

func textColumn(text *string) string {
	if text == nil || *text == "" {
		return "-"
	}
	return *text
}

func localTime(seconds float64, layout string) string {
	return time.Unix(int64(seconds), 0).Format(layout)
}

// RunCLI is the operator command: list | add | delete | ban | unban | bans | modlog | backup |
// restore. It returns the process exit code and never echoes a password.
func RunCLI(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	global := flag.NewFlagSet("accounts", flag.ContinueOnError)
	global.SetOutput(stderr)
	dbPath := global.String("db", "nexlab-accounts.sqlite3", "SQLite file")
	if err := global.Parse(args); err != nil {
		return 2
	}
	if global.NArg() == 0 {
		fmt.Fprintln(stderr, "usage: accounts [--db FILE] list|add|delete|ban|unban|bans|modlog|backup|restore")
		return 2
	}
	command, rest := global.Arg(0), global.Args()[1:]

	flags := flag.NewFlagSet(command, flag.ContinueOnError)
	flags.SetOutput(stderr)
	pidText := flags.String("pid", "", "principal id (decimal or 0x-hex)")
	ipText := flags.String("ip", "", "source address")
	reason := flags.String("reason", "", "short reason kept in the database")
	hours := flags.Float64("hours", 0, "ban for this many hours (default: for good)")
	limit := flags.Int("limit", 50, "number of lines")
	passwordStdin := flags.Bool("password-stdin", false, "read the password from standard input (scripts)")
	positional, err := parseMixed(flags, rest)
	if err != nil {
		return 2
	}
	hoursGiven := false
	flags.Visit(func(f *flag.Flag) { hoursGiven = hoursGiven || f.Name == "hours" })

	need := map[string]int{"add": 1, "delete": 1, "backup": 1, "restore": 1}
	known := map[string]bool{"list": true, "bans": true, "modlog": true, "ban": true, "unban": true}
	wanted, takesArgument := need[command]
	if !takesArgument && !known[command] {
		fmt.Fprintf(stderr, "unknown command: %s\n", command)
		return 2
	}
	if len(positional) != wanted {
		fmt.Fprintf(stderr, "%s: expected %d argument(s)\n", command, wanted)
		return 2
	}

	store, err := Open(*dbPath)
	if err != nil {
		fmt.Fprintf(stderr, "cannot open %s: %v\n", *dbPath, err)
		return 1
	}
	defer store.Close()

	switch command {
	case "list":
		err = list(store, stdout)
	case "bans":
		err = listBans(store, stdout)
	case "modlog":
		err = listLog(store, stdout, *limit)
	case "ban", "unban":
		if *pidText == "" && *ipText == "" {
			fmt.Fprintf(stderr, "%s: give --pid and/or --ip\n", command)
			return 2
		}
		var pid *uint32
		if pid, err = optionalPID(*pidText); err == nil {
			if command == "ban" {
				var duration *float64
				if hoursGiven {
					duration = hours
				}
				if err = store.AddBan(pid, *ipText, *reason, duration); err == nil {
					fmt.Fprintln(stdout, "banned")
				}
			} else if err = store.Unban(pid, *ipText); err == nil {
				fmt.Fprintln(stdout, "unbanned")
			}
		}
	case "delete":
		var pid uint32
		if pid, err = ParsePID(positional[0]); err == nil {
			var removed bool
			if removed, err = store.Delete(pid); err == nil {
				if removed {
					fmt.Fprintln(stdout, "deleted")
				} else {
					fmt.Fprintln(stdout, "no such account")
				}
			}
		}
	case "backup":
		if err = store.Backup(positional[0]); err == nil {
			fmt.Fprintf(stdout, "backup written to %s\n", positional[0])
		}
	case "restore":
		if err = store.Restore(positional[0]); err == nil {
			count, _ := store.Count()
			fmt.Fprintf(stdout, "restored from %s (%d accounts)\n", positional[0], count)
		}
	case "add":
		err = add(store, positional[0], *passwordStdin, stdin, stdout)
	}
	if err != nil {
		fmt.Fprintf(stderr, "refused: %v\n", err)
		return 1
	}
	return 0
}

func list(store *Store, stdout io.Writer) error {
	pids, err := store.PIDs()
	if err != nil {
		return err
	}
	for _, pid := range pids {
		fmt.Fprintf(stdout, "%08x\n", pid)
	}
	fmt.Fprintf(stdout, "%d account(s) in %s\n", len(pids), store.Path)
	return nil
}

func listBans(store *Store, stdout io.Writer) error {
	bans, err := store.Bans()
	if err != nil {
		return err
	}
	for _, ban := range bans {
		until := "for good"
		if ban.Expires != nil {
			until = "until " + localTime(*ban.Expires, "2006-01-02 15:04")
		}
		fmt.Fprintf(stdout, "pid=%-10s ip=%-16s %-22s %s\n", pidColumn(ban.PID), textColumn(ban.IP), until, ban.Reason)
	}
	return nil
}

func listLog(store *Store, stdout io.Writer, limit int) error {
	entries, err := store.ModLog(limit)
	if err != nil {
		return err
	}
	for i := len(entries) - 1; i >= 0; i-- {
		entry := entries[i]
		detail := ""
		if entry.Detail != nil {
			detail = *entry.Detail
		}
		fmt.Fprintf(stdout, "%s %-7s pid=%-10s ip=%-16s %s\n", localTime(entry.At, "2006-01-02 15:04:05"),
			entry.Action, pidColumn(entry.PID), textColumn(entry.IP), detail)
	}
	return nil
}

func add(store *Store, pidText string, fromStdin bool, stdin io.Reader, stdout io.Writer) error {
	pid, err := ParsePID(pidText)
	if err != nil {
		return err
	}
	var password string
	if fromStdin {
		line, err := bufio.NewReader(stdin).ReadString('\n')
		if err != nil && err != io.EOF {
			return err
		}
		password = strings.TrimRight(line, "\r\n")
	} else {
		fmt.Fprint(stdout, "NEX password (16 letters or digits): ")
		secret, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(stdout)
		if err != nil {
			return err
		}
		password = string(secret)
	}
	status, err := store.Register(pid, password)
	if err != nil {
		return err
	}
	fmt.Fprintf(stdout, "%s: pid %08x\n", status, pid)
	return nil
}
