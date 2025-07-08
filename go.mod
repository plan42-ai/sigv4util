module github.com/debugging-sucks/sigv4util

go 1.23.1

require (
	github.com/aws/aws-sdk-go-v2 v1.30.5
	github.com/aws/aws-sdk-go-v2/credentials v1.17.32
	github.com/debugging-sucks/clock v1.1.3
	github.com/stretchr/testify v1.9.0
)

require (
	github.com/aws/smithy-go v1.20.4 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

replace github.com/debugging-sucks/clock => ../clock
