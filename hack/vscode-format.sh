#!/bin/bash

# this script reads c program from stdin and passes it through indent twice
indent <&0 | indent