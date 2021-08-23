EXEC   := nltrace
SRCS   := main.c
OBJS   := main.o
LDLIBS := $(shell pkg-config --libs libmnl)
CFLAGS := $(shell pkg-config --cflags libmnl) -I./
CFLAGS += -g -Og -W -Wall -Wextra -Wno-unused-parameter

all: $(EXEC)

$(EXEC): $(OBJS)
	$(CC) -o $@ $^ $(LDLIBS)

clean:
	$(RM) $(EXEC) $(OBJS)

distclean: clean
	$(RM) *.o *~ *.bak