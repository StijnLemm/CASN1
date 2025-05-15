#!/bin/zsh

mkdir -p ./build
time clang++ -I./include --std=c++17 main.cpp -o ./build/program && ./build/program
