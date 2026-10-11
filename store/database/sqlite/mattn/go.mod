module github.com/markusnieminen1/basic-auth/store/database/sqlite/mattn

go 1.26.0

require (
	github.com/markusnieminen1/basic-auth v0.0.0
	github.com/mattn/go-sqlite3 v1.14.52
)

// Local development: use the checkout instead of a published version.
replace github.com/markusnieminen1/basic-auth => ../../../..
