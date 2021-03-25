  
.: generate

generate:
	@echo "schema"
	@protoc -I=./ \
    --go_opt=paths=source_relative \
	--go_out=./ ./*.proto