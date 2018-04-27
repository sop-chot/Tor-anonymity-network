package print

import (
	"fmt"
	"os"
	"time"
)

var debugPrint = true
var errorPrint = true
var infoPrint = true
var logPrint = true
var encryptionPrint = true

const (
	ONIONLIB   = "onionlib"
	ONION_NODE = "onion-node"
)

// Log ... a struct that represents an obj that triggers log methods
type Log struct {
	file *os.File
	name string
}

// StartLog ... Start file log
// returns a Log struct
func StartLog(entityName string) Log {
	timestamp := time.Now()
	fileName := entityName + "_" + timestamp.Format(time.RFC3339) + ".txt"

	file, _ := os.Create(fileName)
	timeString := "[" + timestamp.Format(time.RFC3339Nano) + "]"
	file.WriteString(timeString + " Starting log for " + entityName + "... \n")

	return Log{
		file: file,
		name: entityName,
	}
}

// Error ... prints error to console and log
func (log *Log) Error(err error, method string) {
	timestamp := time.Now()
	timeString := "[" + timestamp.Format(time.RFC3339Nano) + "]"

	// TODO: figure out the correct format
	//errString := fmt.Sprintf("%#v", err)
	errString := err.Error()

	msg := timeString + "[" + log.name + "]" + "[ERROR]" + " " + method + ": " + errString
	fmt.Println(msg)
	log.file.WriteString(msg + "\n")
}

// Info ... prints debug message to console and log
func (log *Log) Info(method string, msg string, obj interface{}) {
	timestamp := time.Now()
	timeString := "[" + timestamp.Format(time.RFC3339Nano) + "]"

	// TODO: figure out the correct format
	objString := fmt.Sprintf("%#v", obj)

	if obj != nil {
		msg = timeString + "[" + log.name + "]" + "[INFO]" + " " + method + ": " + msg + ": " + objString
	} else {
		msg = timeString + "[" + log.name + "]" + "[INFO]" + " " + method + ": " + msg
	}
	fmt.Println(msg)
	log.file.WriteString(msg + "\n")
}

// Error ... prints error
func Error(file string, err error, method string) {
	if errorPrint {
		timeString := "[" + time.Now().Format(time.RFC3339Nano) + "]"
		fmt.Println()
		if err != nil {
			fmt.Println(timeString+"[ERROR]["+file+"]", method, err)
		}
	}
}

// Debug ... prints debug message
func Debug(file string, method string, msg string, obj interface{}) {
	if debugPrint {
		fmt.Println()
		timeString := "[" + time.Now().Format(time.RFC3339Nano) + "]"
		if obj != nil {
			fmt.Println(timeString+"[DEBUG]["+file+"]", method, ":", msg, ":", obj)
		} else {
			fmt.Println(timeString+"[DEBUG]["+file+"]", method, ":", msg)
		}
	}
}

// Info ... prints info message
func Info(file string, method string, msg string, obj interface{}) {
	if infoPrint {
		fmt.Println()
		timeString := "[" + time.Now().Format(time.RFC3339Nano) + "]"

		if obj != nil {
			fmt.Println(timeString+"[INFO]["+file+"]", method, ":", msg, ":", obj)
		} else {
			fmt.Println(timeString+"[INFO]["+file+"]", method, ":", msg)
		}
	}
}

// Encryption ... prints message before or after encryptio
func Encryption(file string, method string, state string, before []byte, after []byte) {
	if encryptionPrint {
		fmt.Println()
		timeString := "[" + time.Now().Format(time.RFC3339Nano) + "]"

		fmt.Println(timeString+"[ENCRYPTION]"+"["+file+"]", method+":", state)
		fmt.Println(timeString + "[BEFORE]" + fmt.Sprintf("[%x]", before))
		fmt.Println(timeString + "[AFTER]" + fmt.Sprintf("[%x]", after))
	}
}
