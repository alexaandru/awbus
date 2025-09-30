export GOEXPERIMENT=jsonv2

all: fmt lint actionlint vulncheck deadcode test

test:
	@go test -race -vet all -coverprofile=unit.cov -covermode=atomic -race -count=5 $(OPTS) ./...
	@go tool cover -func=unit.cov|tail -n1
	@go tool -modfile=tools/go.mod stampli -quiet -coverage=$$(go tool cover -func=unit.cov|tail -n1|tr -s "\t"|cut -f3|tr -d "%")

unit.cov: test

lint:
	@go run golang.org/x/tools/gopls/internal/analysis/modernize/cmd/modernize@latest -test ./...
	@go tool -modfile=tools/go.mod golangci-lint config verify
	@go tool -modfile=tools/go.mod golangci-lint run

lint-%:
	@go tool -modfile=tools/go.mod golangci-lint --enable-only="$(patsubst lint-%,%,$@)" run

actionlint:
	@go tool -modfile=tools/go.mod actionlint $(OPTS)

vulncheck:
	@echo "Cannot run, see https://github.com/golang/go/issues/73871"
	@#go tool -modfile=tools/go.mod govulncheck ./...

deadcode:
	@go tool -modfile=tools/go.mod deadcode -test ./...

fmt:
	@go fmt ./...
	@go tool -modfile=tools/go.mod goimports -local github.com/alexaandru -l -w .
	@go run mvdan.cc/gofumpt@v0.8.0 -l -w -extra .

clean:
	@rm -f awbus awbus.test *.cov coverage.html
	@killall -q godoc || true
