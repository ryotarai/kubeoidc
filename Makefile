.PHONY: gox

gox:
	gox -os="darwin windows linux" -arch=amd64 -output="release/{{.Dir}}_{{.OS}}_{{.Arch}}"
