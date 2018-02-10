################################################################################
# Automatically-generated file. Do not edit!
################################################################################

SHELL := cmd.exe
RM := rm -rf

USER_OBJS :=

LIBS := 
PROJ := 

O_SRCS := 
C_SRCS := 
S_SRCS := 
S_UPPER_SRCS := 
OBJ_SRCS := 
ASM_SRCS := 
PREPROCESSING_SRCS := 
OBJS := 
OBJS_AS_ARGS := 
C_DEPS := 
C_DEPS_AS_ARGS := 
EXECUTABLES := 
OUTPUT_FILE_PATH :=
OUTPUT_FILE_PATH_AS_ARGS :=
AVR_APP_PATH :=$$$AVR_APP_PATH$$$
QUOTE := "
ADDITIONAL_DEPENDENCIES:=
OUTPUT_FILE_DEP:=
LIB_DEP:=
LINKER_SCRIPT_DEP:=

# Every subdirectory with source files must be described here
SUBDIRS := 


# Add inputs and outputs from these tool invocations to the build variables 
C_SRCS +=  \
../aes.c \
../baseconv.c \
../bignum256.c \
../bip32.c \
../ecdsa.c \
../endian.c \
../hash.c \
../hmac_drbg.c \
../hmac_sha512.c \
../main.c \
../messages.pb.c \
../pbkdf2.c \
../pb_decode.c \
../pb_encode.c \
../prandom.c \
../ripemd160.c \
../sha256.c \
../test_helpers.c \
../wallet.c \
../xex.c


PREPROCESSING_SRCS += 


ASM_SRCS += 


OBJS +=  \
aes.o \
baseconv.o \
bignum256.o \
bip32.o \
ecdsa.o \
endian.o \
hash.o \
hmac_drbg.o \
hmac_sha512.o \
main.o \
messages.pb.o \
pbkdf2.o \
pb_decode.o \
pb_encode.o \
prandom.o \
ripemd160.o \
sha256.o \
test_helpers.o \
wallet.o \
xex.o

OBJS_AS_ARGS +=  \
aes.o \
baseconv.o \
bignum256.o \
bip32.o \
ecdsa.o \
endian.o \
hash.o \
hmac_drbg.o \
hmac_sha512.o \
main.o \
messages.pb.o \
pbkdf2.o \
pb_decode.o \
pb_encode.o \
prandom.o \
ripemd160.o \
sha256.o \
test_helpers.o \
wallet.o \
xex.o

C_DEPS +=  \
aes.d \
baseconv.d \
bignum256.d \
bip32.d \
ecdsa.d \
endian.d \
hash.d \
hmac_drbg.d \
hmac_sha512.d \
main.d \
messages.pb.d \
pbkdf2.d \
pb_decode.d \
pb_encode.d \
prandom.d \
ripemd160.d \
sha256.d \
test_helpers.d \
wallet.d \
xex.d

C_DEPS_AS_ARGS +=  \
aes.d \
baseconv.d \
bignum256.d \
bip32.d \
ecdsa.d \
endian.d \
hash.d \
hmac_drbg.d \
hmac_sha512.d \
main.d \
messages.pb.d \
pbkdf2.d \
pb_decode.d \
pb_encode.d \
prandom.d \
ripemd160.d \
sha256.d \
test_helpers.d \
wallet.d \
xex.d

OUTPUT_FILE_PATH +=test6.elf

OUTPUT_FILE_PATH_AS_ARGS +=test6.elf

ADDITIONAL_DEPENDENCIES:=

OUTPUT_FILE_DEP:= ./makedep.mk

LIB_DEP+= 

LINKER_SCRIPT_DEP+= 


# AVR32/GNU C Compiler









































./%.o: .././%.c
	@echo Building file: $<
	@echo Invoking: AVR/GNU C Compiler : 5.4.0
	$(QUOTE)F:\Atmel\Studio\7.0\toolchain\avr8\avr8-gnu-toolchain\bin\avr-gcc.exe$(QUOTE)  -x c -funsigned-char -funsigned-bitfields -DDEBUG  -I"F:\Atmel\Studio\7.0\Packs\Atmel\ATmega_DFP\1.2.203\include"  -O1 -ffunction-sections -fdata-sections -fpack-struct -fshort-enums -mrelax -g2 -Wall -mmcu=atmega128 -B "F:\Atmel\Studio\7.0\Packs\Atmel\ATmega_DFP\1.2.203\gcc\dev\atmega128" -c -std=gnu99 -MD -MP -MF "$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -MT"$(@:%.o=%.o)"   -o "$@" "$<" 
	@echo Finished building: $<
	



# AVR32/GNU Preprocessing Assembler



# AVR32/GNU Assembler




ifneq ($(MAKECMDGOALS),clean)
ifneq ($(strip $(C_DEPS)),)
-include $(C_DEPS)
endif
endif

# Add inputs and outputs from these tool invocations to the build variables 

# All Target
all: $(OUTPUT_FILE_PATH) $(ADDITIONAL_DEPENDENCIES)

$(OUTPUT_FILE_PATH): $(OBJS) $(USER_OBJS) $(OUTPUT_FILE_DEP) $(LIB_DEP) $(LINKER_SCRIPT_DEP)
	@echo Building target: $@
	@echo Invoking: AVR/GNU Linker : 5.4.0
	$(QUOTE)F:\Atmel\Studio\7.0\toolchain\avr8\avr8-gnu-toolchain\bin\avr-gcc.exe$(QUOTE) -o$(OUTPUT_FILE_PATH_AS_ARGS) $(OBJS_AS_ARGS) $(USER_OBJS) $(LIBS) -Wl,-Map="test6.map" -Wl,--start-group -Wl,-lm  -Wl,--end-group -Wl,--gc-sections -mrelax -mmcu=atmega128 -B "F:\Atmel\Studio\7.0\Packs\Atmel\ATmega_DFP\1.2.203\gcc\dev\atmega128"  
	@echo Finished building target: $@
	"F:\Atmel\Studio\7.0\toolchain\avr8\avr8-gnu-toolchain\bin\avr-objcopy.exe" -O ihex -R .eeprom -R .fuse -R .lock -R .signature -R .user_signatures  "test6.elf" "test6.hex"
	"F:\Atmel\Studio\7.0\toolchain\avr8\avr8-gnu-toolchain\bin\avr-objcopy.exe" -j .eeprom  --set-section-flags=.eeprom=alloc,load --change-section-lma .eeprom=0  --no-change-warnings -O ihex "test6.elf" "test6.eep" || exit 0
	"F:\Atmel\Studio\7.0\toolchain\avr8\avr8-gnu-toolchain\bin\avr-objdump.exe" -h -S "test6.elf" > "test6.lss"
	"F:\Atmel\Studio\7.0\toolchain\avr8\avr8-gnu-toolchain\bin\avr-objcopy.exe" -O srec -R .eeprom -R .fuse -R .lock -R .signature -R .user_signatures "test6.elf" "test6.srec"
	"F:\Atmel\Studio\7.0\toolchain\avr8\avr8-gnu-toolchain\bin\avr-size.exe" "test6.elf"
	
	





# Other Targets
clean:
	-$(RM) $(OBJS_AS_ARGS) $(EXECUTABLES)  
	-$(RM) $(C_DEPS_AS_ARGS)   
	rm -rf "test6.elf" "test6.a" "test6.hex" "test6.lss" "test6.eep" "test6.map" "test6.srec" "test6.usersignatures"
	