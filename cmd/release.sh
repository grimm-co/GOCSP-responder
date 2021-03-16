#!/bin/bash

NAME=gocsp
OUTPUT=../build

mkdir -p ${OUTPUT}

CGO_ENABLED=0 go build -o ${OUTPUT}/${NAME} ./*.go
