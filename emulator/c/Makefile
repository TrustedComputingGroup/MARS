BUILD ?= ../build
ALL := demo dispa disps disp2 disp3

ALLB := $(ALL:%=$(BUILD)/%)

all: $(BUILD) $(ALLB)

# check for local install of openssl3
OSL3DIR ?= ../openssl/openssl-openssl-3.0
ifneq ($(wildcard $(OSL3DIR)), )
    OSL3INC := -I $(OSL3DIR)/include -Wno-deprecated-declarations
    OSL3LIB := $(BUILD)/libcrypto.so
else
    OSL3INC := -Wno-deprecated-declarations
    OSL3LIB := -lcrypto
endif

$(BUILD)/dispa: hw_ascon.h dispatcher.c $(BUILD)/vget.o $(BUILD)/mars_ascon.o $(BUILD)/hw_ascon.o $(BUILD)/ascon.a
	gcc -o $@ -include $^ $(BUILD)/libtinycbor.so

$(BUILD)/disps: hw_she.h dispatcher.c $(BUILD)/vget.o $(BUILD)/mars_she.o $(BUILD)/hw_she.o $(BUILD)/aes.o
	gcc -o $@ -include $^ $(BUILD)/libtinycbor.so

$(BUILD)/disp2: hw_sha2.h dispatcher.c $(BUILD)/vget.o $(BUILD)/mars_sha2.o $(BUILD)/hw_sha2.o $(OSL3LIB)
	gcc -o $@ -include $^ $(BUILD)/libtinycbor.so

$(BUILD)/disp3: hw_sha3.h dispatcher.c $(BUILD)/vget.o $(BUILD)/mars_sha3.o $(BUILD)/hw_sha3.o $(OSL3LIB)
	gcc -o $@ -include $^ $(BUILD)/libtinycbor.so

$(BUILD):
	mkdir $@

$(BUILD)/hw_she.o: hw_she.c hw_she.h
	gcc -o $@ -c $<

$(BUILD)/aes.o: ../aes/aes.c
	gcc -o $@ -c $<

$(BUILD)/mars_she.o: hw_she.h mars.c mars.h
	gcc -o $@ -include $< -c mars.c

##############################################################

$(BUILD)/hw_sha2.o: hw_sha2.c hw_sha2.h
	gcc -o $@ -c $< $(OSL3INC)

$(BUILD)/mars_sha2.o: hw_sha2.h mars.c mars.h
	gcc -o $@ -include $< -c mars.c

##############################################################

$(BUILD)/hw_sha3.o: hw_sha3.c hw_sha3.h
	gcc -o $@ -c $< $(OSL3INC)

$(BUILD)/mars_sha3.o: hw_sha3.h mars.c mars.h
	gcc -o $@ -include $< -c mars.c

##############################################################

$(BUILD)/hw_ascon.o: hw_ascon.c hw_ascon.h
	gcc -o $@ -c $<

$(BUILD)/mars_ascon.o: hw_ascon.h mars.c mars.h
	gcc -o $@ -include $< -c mars.c

##############################################################

$(BUILD)/%.o: %.c mars.h
	gcc -o $@ -c $<

$(BUILD)/api.o $(BUILD)/demo.o: api.h mars.h

$(BUILD)/demo: $(BUILD)/demo.o $(BUILD)/api.o $(BUILD)/vget.o $(BUILD)/libtinycbor.so
	gcc -o $@ $^

clean:
	rm $(BUILD)/*.o $(ALLB)
	rmdir $(BUILD)

