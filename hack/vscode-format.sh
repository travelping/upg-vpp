#!/bin/bash

# this script reads c program from stdin and passes it through indent twice
# needs to be run from within the buildenv container
indent <&0 | indent