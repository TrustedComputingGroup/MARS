BUILD ?= ../build

all: $(BUILD) $(BUILD)/mars_cbor.a

$(BUILD):
	mkdir -p $(BUILD)

MARS_PROFILE ?= ../c/hw_sha2.h
CFLAGS = -O2  -I$(BUILD) -I./zcbor/include -I../c  -include $(MARS_PROFILE)

$(BUILD)/mars_decoder.c $(BUILD)/mars_decoder.h: mars.cddl
	zcbor -c $< code -d -t mars_command --oc $@ --oh $(BUILD)/mars_decoder.h

$(BUILD)/mars_encoder.c $(BUILD)/mars_encoder.h: mars.cddl
	zcbor -c $< code -e -t mars_response --oc $@ --oh $(BUILD)/mars_encoder.h

$(BUILD)/mars_encoder.o: $(BUILD)/mars_encoder.c
	gcc -c $(CFLAGS) -o $@ $<

$(BUILD)/mars_decoder.o: $(BUILD)/mars_decoder.c
	gcc -c $(CFLAGS) -o $@ $<

$(BUILD)/mars_cbor.o: mars_cbor.c $(BUILD)/mars_encoder.h $(BUILD)/mars_decoder.h
	gcc -c $(CFLAGS) -o $@ $<

$(BUILD)/zcbor_common.o: ./zcbor/src/zcbor_common.c
	gcc -c $(CFLAGS) -o $@ $<

$(BUILD)/zcbor_decode.o: ./zcbor/src/zcbor_decode.c
	gcc -c $(CFLAGS) -o $@ $<

$(BUILD)/zcbor_encode.o: ./zcbor/src/zcbor_encode.c
	gcc -c $(CFLAGS) -o $@ $<

$(BUILD)/mars_cbor.a: $(BUILD)/zcbor_encode.o $(BUILD)/zcbor_decode.o $(BUILD)/zcbor_common.o $(BUILD)/mars_encoder.o $(BUILD)/mars_decoder.o $(BUILD)/mars_cbor.o
	ar cr $(BUILD)/mars_cbor.a $^

clean:
	rm $(BUILD)/*
	rmdir $(BUILD)

