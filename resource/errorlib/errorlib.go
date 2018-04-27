/*
	This is a library for error definitions that allows onion application to explicitly check
	for specific errors that occurred.
*/

package errorlib

import "fmt"

// Contains node address (IP:port) that client node cannot connect to.
type DisconnectedError string

func (e DisconnectedError) Error() string {
	return fmt.Sprintf("Cannot connect to [%s]", string(e))
}

// Contains number of available onion nodes
type InsufficientNumberOfOnionNodeError uint32

func (e InsufficientNumberOfOnionNodeError) Error() string {
	return fmt.Sprintf("Not enough onion nodes [%d] to construct a circuit", uint32(e))
}

// Contains onion node address (IP:port) that client node fails to negotiate a shared key
type InvalidKeyExchangeError string

func (e InvalidKeyExchangeError) Error() string {
	return fmt.Sprintf("Invalid key exchange with onion node [%s]", string(e))
}

// Contains circuit ID that already exists between two nodes
type CircuitIDAlreadyExistsError string

func (e CircuitIDAlreadyExistsError) Error() string {
	return fmt.Sprintf("Circuit ID [%s] already exists", string(e))
}

// Contains command received and command expected
type InvalidCommandReceivedError string

func (e InvalidCommandReceivedError) Error() string {
	return fmt.Sprintf("Received Incorrected Command [%s]", string(e))
}

type InvalidPortNumberError uint32

func (e InvalidPortNumberError) Error() string {
	return fmt.Sprintf("Port number [%d] is not allowed", uint32(e))
}

type OnionEncryptionError string

func (e OnionEncryptionError) Error() string {
	return fmt.Sprintf("Failed to encrypt onion for circuit: [%s]", string(e))
}

type OnionDecryptionError string

func (e OnionDecryptionError) Error() string {
	return fmt.Sprintf("Failed to decrypt onion for circuit: [%s]", string(e))
}

type ServersUnavailableError string

func (e ServersUnavailableError) Error() string {
	return fmt.Sprintf("There are no servers currently available to connect to")
}

type InvalidCircuitStructureError string

func (e InvalidCircuitStructureError) Error() string {
	return fmt.Sprintf("Circuit [%s] structure is invalid", string(e))
}

type RetryError string

func (e RetryError) Error() string {
	return fmt.Sprintf("Unable to process request for web address [%s]", string(e))
}

type HttpError string

func (e HttpError) Error() string {
	return fmt.Sprintf("%s", string(e))
}

type CorruptPacketError struct{}

func (e CorruptPacketError) Error() string {
	return fmt.Sprintf("A corrupt packet was detected unable to complete request")
}

type CircuitGenerationError struct{}

func (e CircuitGenerationError) Error() string {
	return fmt.Sprintf("Unable to generate a circuit to complete request")
}
