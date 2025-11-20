#!/bin/bash
# Script to enterprise-specific configure Git merge drivers

# Override Go modules driver. This works for OSS and CEE as we execute go mod
# tidy && go mod vendor regardless of the make gomod-override outcome.
git config merge.go-mod-tidy.driver "make gomod-override || (go mod tidy && go mod vendor) && (go mod tidy && go mod vendor)"
