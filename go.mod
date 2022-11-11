module github.com/hickford/git-credential-oauth

go 1.19

require golang.org/x/oauth2 v0.8.0

require (
	github.com/golang/protobuf v1.5.3 // indirect
	github.com/google/go-cmp v0.5.9 // indirect
	golang.org/x/net v0.10.0 // indirect
	google.golang.org/appengine v1.6.7 // indirect
	google.golang.org/protobuf v1.30.0 // indirect
)

replace golang.org/x/oauth2 => github.com/hickford/oauth2 v0.0.0-20230316201659-ccad9d9a87ba
