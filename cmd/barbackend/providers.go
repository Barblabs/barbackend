package main

import (
	"barbackend/internal/cmdb"
	"barbackend/internal/cmdb/itop"
)

func providers() cmdb.Providers {
	return cmdb.Providers{"itop": itop.Provider{}}
}
