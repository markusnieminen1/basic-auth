module github.com/markusnieminen1/basic-auth/components/hashing/bcrypt

go 1.26.0

require github.com/markusnieminen1/basic-auth v0.0.0

require golang.org/x/crypto v0.57.0

// Local development: use the checkout instead of a published version.
replace github.com/markusnieminen1/basic-auth => ../../..
