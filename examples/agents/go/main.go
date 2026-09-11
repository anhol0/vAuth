package main

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/godbus/dbus/v5"
)

const (
	service   = "org.lamellix.vAuth"
	path      = dbus.ObjectPath("/org/lamellix/vAuth")
	iface     = "org.lamellix.vAuth.UserInteraction1"
	stateName = iface + ".StateChanged"
)

var terminalStates = map[string]bool{
	"presence_approved":      true,
	"presence_denied":        true,
	"verification_succeeded": true,
	"verification_failed":    true,
	"cancelled":              true,
	"timed_out":              true,
}

var knownStates = map[string]bool{
	"presence_required":      true,
	"presence_approved":      true,
	"presence_denied":        true,
	"verification_started":   true,
	"fingerprint_required":   true,
	"fingerprint_failed":     true,
	"password_required":      true,
	"verification_succeeded": true,
	"verification_failed":    true,
	"cancelled":              true,
	"timed_out":              true,
}

func main() {
	conn, err := dbus.ConnectSystemBus()
	if err != nil {
		fatal(err)
	}
	defer conn.Close()

	if err := conn.AddMatchSignal(
		dbus.WithMatchSender(service),
		dbus.WithMatchObjectPath(path),
		dbus.WithMatchInterface(iface),
		dbus.WithMatchMember("StateChanged"),
	); err != nil {
		fatal(err)
	}

	signals := make(chan *dbus.Signal, 16)
	conn.Signal(signals)
	defer conn.RemoveSignal(signals)

	object := conn.Object(service, path)
	var generation uint64
	if err := object.Call(iface+".RegisterAgent", 0).Store(&generation); err != nil {
		fatal(err)
	}
	if generation == 0 {
		fatal(errors.New("daemon returned generation zero"))
	}
	defer object.Call(iface+".UnregisterAgent", 0)
	fmt.Printf("registered generation %d\n", generation)

	reader := bufio.NewReader(os.Stdin)
	var activeRequest uint64
	for signal := range signals {
		if signal.Name != stateName || len(signal.Body) != 5 {
			continue
		}
		signalGeneration, ok1 := signal.Body[0].(uint64)
		requestID, ok2 := signal.Body[1].(uint64)
		state, ok3 := signal.Body[2].(string)
		operation, ok4 := signal.Body[3].(string)
		rpID, ok5 := signal.Body[4].(string)
		if !ok1 || !ok2 || !ok3 || !ok4 || !ok5 ||
			signalGeneration != generation || requestID == 0 || !knownStates[state] {
			continue
		}

		if state == "presence_required" || state == "verification_started" {
			if activeRequest != 0 && activeRequest != requestID {
				continue
			}
			activeRequest = requestID
		} else if activeRequest != requestID {
			continue
		}

		fmt.Printf("%s: %s for RP %s\n", state, operation, rpID)
		switch state {
		case "presence_required":
			fmt.Print("Approve? [y]es/[n]o/[c]ancel: ")
			answer, readErr := reader.ReadString('\n')
			answer = strings.ToLower(strings.TrimSpace(answer))
			if readErr != nil || strings.HasPrefix(answer, "c") {
				err = object.Call(
					iface+".CancelInteraction", 0, generation, requestID,
				).Err
			} else {
				err = object.Call(
					iface+".RespondToPresence",
					0,
					generation,
					requestID,
					strings.HasPrefix(answer, "y"),
				).Err
			}
		case "password_required":
			// Console strings cannot be reliably erased. A real UI should call
			// submitPassword with a protected mutable byte slice.
			err = object.Call(
				iface+".CancelInteraction", 0, generation, requestID,
			).Err
		}
		if err != nil {
			fmt.Fprintf(os.Stderr, "interaction reply failed: %v\n", err)
			err = nil
		}
		if terminalStates[state] {
			activeRequest = 0
		}
	}
}

func submitPassword(
	object dbus.BusObject,
	generation uint64,
	requestID uint64,
	password []byte,
) (err error) {
	defer func() {
		clear(password)
	}()
	if requestID == 0 || len(password) > 1024 || bytes.IndexByte(password, 0) >= 0 {
		return errors.New("password must be at most 1024 bytes without NUL")
	}

	readEnd, writeEnd, err := os.Pipe()
	if err != nil {
		return err
	}
	defer readEnd.Close()

	written := 0
	for written < len(password) {
		var count int
		count, err = writeEnd.Write(password[written:])
		if err != nil {
			writeEnd.Close()
			return err
		}
		if count == 0 {
			writeEnd.Close()
			return errors.New("password pipe made no write progress")
		}
		written += count
	}
	if err = writeEnd.Close(); err != nil {
		return err
	}

	return object.Call(
		iface+".SubmitPassword",
		0,
		generation,
		requestID,
		dbus.UnixFD(readEnd.Fd()),
	).Err
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "vAuth agent example:", err)
	os.Exit(1)
}
