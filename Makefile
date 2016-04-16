all:
	gcc -O2 -Wall -Wextra -pedantic -c sigie.c
	ar -cvq libsigie.a sigie.o
test: all
	gcc -O2 -Wall -Wextra -pedantic test.c libsigie.a -o sigie
clean:
	rm -f *.o libsigie.a sigie
