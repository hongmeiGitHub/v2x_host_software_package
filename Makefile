SRC=$(PWD)

#SUB_DIR2=openssl
SUB_SRC=src
SUB_INC=include
SUB_TEST=testvectors
INC_DIR=/usr/lib/arm-linux-gnueabihf/
EXEC_OBJS=$(SRC)/$(SUB_SRC)/v2xtool.o

STATIC_LIB_OBJS=$(SRC)/$(SUB_SRC)/sls37v2x_prototype_API.o \
    $(SRC)/$(SUB_SRC)/common.o \
    $(SRC)/$(SUB_SRC)/crypto_wrapper.o \
    $(SRC)/$(SUB_SRC)/sls37v2x_prototype_SPI_protocol.o \
    $(SRC)/$(SUB_SRC)/SPI_master_driver.o

EXEC_NAME=v2xtool

STATIC_LIB_NAME=sls37v2x_prototype_API.a

INC_FLAGS= -I$(SRC) -I$(SRC)/$(SUB_SRC) -I$(SRC)/$(SUB_INC) -I$(INC_DIR) -I$(SRC)/$(SUB_TEST)
STATIC_LIB_PATH=$(SRC)

CC=$(CROSS_COMPILE)gcc
CXX=$(CROSS_COMPILE)g++
AR=$(CROSS_COMPILE)ar
LD=$(CROSS_COMPILE)ld
RANLIB=$(CROSS_COMPILE)ranlib
CFLAGS +=-g $(INC_FLAGS) -O2
#CFLAGS +=-g $(INC_FLAGS) -O2 -DEMULATOR

#LDFLAGS += libssl.so.1.1 libcrypto.so.1.1 $(STATIC_LIB_NAME) -lrt
LDFLAGS += $(STATIC_LIB_NAME) -lcrypto -lrt

.PHONY: all

# What needs to be built to make all files and dependencies:
all: $(STATIC_LIB_NAME) $(EXEC_NAME)

$(STATIC_LIB_NAME): $(STATIC_LIB_OBJS)
#	$(CC) $(CFLAGS) -c -o $@ $<
	$(AR) rc $@ $^
	@echo
	$(RANLIB) $@
	@echo

# Create the executable:
$(EXEC_NAME): $(EXEC_OBJS)
	$(CC) -o $(EXEC_NAME) $(EXEC_OBJS) $(LDFLAGS)
	@echo

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<
	@echo

clean:
	rm -f $(EXEC_NAME) $(EXEC_OBJS) $(STATIC_LIB_OBJS) $(STATIC_LIB_NAME) V2X_SPI.log
