CC = gcc
 
# compiler flags:
CFLAGS = -lstdc++
 
# The build target 
TARGET = ipk-sniffer

#Clean
RM = rm -f
 
all: $(TARGET)
			$(CC) $(TARGET).cpp $(CFLAGS) -o $(TARGET)
 
  clean:
			$(RM) $(TARGET)