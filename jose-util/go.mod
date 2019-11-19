module github.com/square/go-jose/jose-util

go 1.12

require (
	github.com/alecthomas/template v0.0.0-20160405071501-a0175ee3bccc // indirect
	github.com/alecthomas/units v0.0.0-20151022065526-2efee857e7cf // indirect
	github.com/square/go-jose/v3 v3.0.0-00010101000000-000000000000
	golang.org/x/crypto v0.0.0-20190513172903-22d7a77e9e5f
	gopkg.in/alecthomas/kingpin.v2 v2.2.6
)

replace github.com/square/go-jose/v3 => ../
