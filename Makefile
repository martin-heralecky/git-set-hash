all: git-set-hash

git-set-hash: main.c
	gcc -Wall -o ./git-set-hash main.c -lm -lgit2 -lcrypto -pthread

clean:
	rm -f ./git-set-hash

install: git-set-hash
	mkdir -p /usr/local/bin
	cp -f ./git-set-hash /usr/local/bin/git-set-hash
	mkdir -p /usr/local/man/man1
	cp -f ./git-set-hash.1 /usr/local/man/man1/git-set-hash.1

uninstall:
	rm -f /usr/local/bin/git-set-hash
