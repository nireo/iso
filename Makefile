iso:
	gcc -O3 -Wextra -Wshadow -Wconversion src/mongoose.c src/base64.c src/entry.pb-c.c src/iso.c src/main.c -o iso -lleveldb -lprotobuf-c -lcrypto -lssl
