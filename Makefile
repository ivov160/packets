all: clean app

run: clean app
	./app ./dump.cap

app:
	gcc -O2 -g -Wall -Wpedantic -Wextra -Werror -D_GNU_SOURCE ./main.c -o ./app -lpcap

clean:
	rm -vf ./app
