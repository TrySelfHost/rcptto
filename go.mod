module github.com/tryselfhost/rcptto

go 1.22

require github.com/jackc/pgx/v5 v5.7.2

require (
	github.com/jackc/pgpassfile v1.0.0 // indirect
	github.com/jackc/pgservicefile v0.0.0-20240606120523-5a60cdf6a761 // indirect
	github.com/jackc/puddle/v2 v2.2.2 // indirect
	golang.org/x/crypto v0.31.0 // indirect
	golang.org/x/sync v0.10.0 // indirect
	golang.org/x/text v0.21.0 // indirect
)

replace gopkg.in/yaml.v3 => github.com/go-yaml/yaml v3.0.1+incompatible

replace gopkg.in/check.v1 => github.com/go-check/check v0.0.0-20161208181325-20d25e280405

replace golang.org/x/crypto => github.com/golang/crypto v0.31.0

replace golang.org/x/text => github.com/golang/text v0.21.0

replace golang.org/x/sync => github.com/golang/sync v0.10.0
