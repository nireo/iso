iso:
	gcc -O3 src/mongoose.c src/entry.pb-c.c src/iso.c src/main.c -o iso -lleveldb -lprotobuf-c
