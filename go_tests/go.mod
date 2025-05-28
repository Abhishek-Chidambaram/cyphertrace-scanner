module example.com/myapp

go 1.19

require (
	github.com/gin-gonic/gin v1.8.1
	github.com/stretchr/testify v1.8.0
	golang.org/x/crypto v0.0.0-20220622213112-05595931fe9d
	github.com/old/package v1.0.0
)

require (
	github.com/bytedance/sonic v1.5.0 // indirect
	github.com/chenzhuoyu/base64x v0.0.0-20211019084208-fb5309c8db06 // indirect
)

replace github.com/old/package => github.com/new/package v1.2.3 