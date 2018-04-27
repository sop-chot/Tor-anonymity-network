package circuitTest

import (
	"fmt"
	"os"

	"../../resource"
)

/* ==========================    Test Methods    ========================== */
func GetXTopology1(nodes []resource.OnionInfo) (chosenNodes []resource.OnionInfo) {
	if len(nodes) < 5 {
		fmt.Println("X topology requires a minimum of 5 nodes")
		os.Exit(1)
	}

	chosenNodes = append(chosenNodes, nodes[0])
	chosenNodes = append(chosenNodes, nodes[1]) // Common node
	chosenNodes = append(chosenNodes, nodes[2])
	for _, val := range chosenNodes {
		fmt.Println(val.Address.String())
	}

	return chosenNodes
}

func GetXTopology2(nodes []resource.OnionInfo) (chosenNodes []resource.OnionInfo) {
	if len(nodes) < 5 {
		fmt.Println("X topology requires a minimum of 5 nodes")
		os.Exit(1)
	}

	chosenNodes = append(chosenNodes, nodes[3])
	chosenNodes = append(chosenNodes, nodes[1]) // Common node
	chosenNodes = append(chosenNodes, nodes[4])

	fmt.Println(" ")
	fmt.Println(" ")
	for _, val := range chosenNodes {
		fmt.Println(val.Address.String())
	}
	return chosenNodes
}

func GetTTopology1(nodes []resource.OnionInfo) (chosenNodes []resource.OnionInfo) {
	if len(nodes) < 5 {
		fmt.Println("T topology requires a minimum of 5 nodes")
		os.Exit(1)
	}

	chosenNodes = append(chosenNodes, nodes[0])
	chosenNodes = append(chosenNodes, nodes[1]) // Common node
	chosenNodes = append(chosenNodes, nodes[2])
	chosenNodes = append(chosenNodes, nodes[3])

	fmt.Println(" ")
	fmt.Println(" ")
	for _, val := range chosenNodes {
		fmt.Println(val.Address.String())
	}
	return chosenNodes
}

func GetTTopology2(nodes []resource.OnionInfo) (chosenNodes []resource.OnionInfo) {
	if len(nodes) < 5 {
		fmt.Println("T topology requires a minimum of 5 nodes")
		os.Exit(1)
	}

	chosenNodes = append(chosenNodes, nodes[4])
	chosenNodes = append(chosenNodes, nodes[1]) // Common node
	chosenNodes = append(chosenNodes, nodes[2])
	chosenNodes = append(chosenNodes, nodes[3])

	fmt.Println(" ")
	fmt.Println(" ")
	for _, val := range chosenNodes {
		fmt.Println(val.Address.String())
	}
	return chosenNodes
}

func GetReverseTTopology1(nodes []resource.OnionInfo) (chosenNodes []resource.OnionInfo) {
	if len(nodes) < 5 {
		fmt.Println("T topology requires a minimum of 5 nodes")
		os.Exit(1)
	}

	chosenNodes = append(chosenNodes, nodes[0])
	chosenNodes = append(chosenNodes, nodes[1])
	chosenNodes = append(chosenNodes, nodes[2]) // Common node
	chosenNodes = append(chosenNodes, nodes[3])

	fmt.Println(" ")
	fmt.Println(" ")
	for _, val := range chosenNodes {
		fmt.Println(val.Address.String())
	}
	return chosenNodes
}

func GetReverseTTopology2(nodes []resource.OnionInfo) (chosenNodes []resource.OnionInfo) {
	if len(nodes) < 5 {
		fmt.Println("T topology requires a minimum of 5 nodes")
		os.Exit(1)
	}

	chosenNodes = append(chosenNodes, nodes[0])
	chosenNodes = append(chosenNodes, nodes[1])
	chosenNodes = append(chosenNodes, nodes[2]) // Common node
	chosenNodes = append(chosenNodes, nodes[4])

	fmt.Println(" ")
	fmt.Println(" ")
	for _, val := range chosenNodes {
		fmt.Println(val.Address.String())
	}
	return chosenNodes
}
