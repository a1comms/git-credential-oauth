module github.com/hickford/git-credential-oauth

go 1.19

require golang.org/x/oauth2 v0.8.0

require (
	github.com/golang/protobuf v1.5.3 // indirect
	golang.org/x/net v0.14.0 // indirect
	google.golang.org/appengine v1.6.7 // indirect
	google.golang.org/protobuf v1.31.0 // indirect
)

replace golang.org/x/oauth2 => ./oauth2
