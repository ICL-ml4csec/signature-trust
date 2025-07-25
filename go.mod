module github.com/ICL-ml4sec/msc-hmj24

go 1.23

require (
	github.com/gorilla/mux v1.8.1
	github.com/sirupsen/logrus v1.9.3
	github.com/spf13/viper v1.20.1
	github.com/stretchr/testify v0.0.0-20240315094613-abcdefabcdef // pseudo-version
	github.com/internal/privatepkg v0.1.0 // possible private/internal package
	rsc.io/quote v1.5.2 // not github URL
	github.com/google/go-cmp v0.6.0 // indirect
	github.com/dgrijalva/jwt-go v3.2.0+incompatible
	github.com/spf13/cobra/v2 v2.9.1
	github.com/spf13/cobra v1.9.0
	github.com/foo/bar v1.5.1
)

exclude github.com/stretchr/testify v1.10.0 // excluded, do not use that version

replace github.com/foo/bar => github.com/forked/bar v1.5.1

replace github.com/local/module => ../local/module // should be skipped (local)
