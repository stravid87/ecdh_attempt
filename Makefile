runproxy:
	go run proxy/proxy.go

buildwasm:
	cd WASM && GOARCH=wasm GOOS=js go build -o ../proxy/static/ecdh.wasm

winwasm:
	set GOARCH=wasm && set GOOS=js && cd WASM && go build -o ../proxy/static/ecdh.wasm

test:
	echo "test call to make"