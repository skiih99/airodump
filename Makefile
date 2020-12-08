all: airodump

airodump: airodump.o main.o
	g++ -o airodump airodump.o main.o -lpcap

airodump.o: airodump.h airodump.cpp
	g++ -c -o airodump.o airodump.cpp

main.o: airodump.h main.cpp
	g++ -c -o main.o main.cpp

clean:
	rm -f airodump
	rm -f *.o