#!/bin/bash

printHelp() {
	echo "Usage: generate_key.sh options"
	echo
	echo "options:"
	echo "-a : Algorithm(RSA, SECP256K1)"
	echo "-o : output"
	echo
	echo "e.g. generate_key.sh -a secp256k1 -o eth.pem"
}

while getopts ":a:o:" opt; do
	case "${opt}" in
	a)
		a=${OPTARG}
		;;
	o)
		p=${OPTARG}
		;;
	*)
		printHelp
		;;
	esac
done

echo "algorithm: $a filename: $p"

case "$a" in
RSA)
	openssl genrsa -out "$p".pem 2048
	;;
SECP256K1)
	openssl ecparam -name secp256k1 -genkey -noout -out "$p".pem
	;;
esac
