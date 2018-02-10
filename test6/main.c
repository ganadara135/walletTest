/*
// S/W Environment : AVR Studio + WINAVR Compiler
// Target : M128
// Crystal: 16MHz
// example : Serial LCD module in Terminal mode test from ATMEGA128 to SLCD
 * Created: 2018-02-07 오전 2:37:14
 * Author : user
	* \brief Entry point for hardware Bitcoin wallet.
	*
	* This file is licensed as described by the file LICENCE.
 */ 

#include <avr/io.h>
#include <avr/interrupt.h>
//#include "c:/WinAVR-20100110/avr/include/avr/iom128.h"

#define  AVR
#include "common.h"


#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <assert.h>
#include <avr/pgmspace.h>
#include "aes.h"
#include "hash.h"
#include "sha256.h"
#include "ecdsa.h"
#include "endian.h"
#include "hmac_sha512.h"
#include "xex.h"
#include "hwinterface.h"

#include "prandom.h"
#include "storage_common.h"

#include "wallet.h"


#include "test_helpers.h"



// 내 모듈은 16MHz 크리스탈사용, 컴파일러에게 안알려주면 1MHz 인식
// _delay_ms()의 최대시간 16.38ms, _delay_us() 최대 시간 48us
#define F_CPU 16000000UL          //UL unsigned long
/*
i >> x  : i의 비트열을 오른쪽으로 x만큼 이동
i << x  : i의 비트열을 왼쪽으로 x만큼 이동
*/



char buff[30];

//static int Putchar(char c, FILE *stream);
void tx0Char(char message);
void tx1Char(char message);

static int Putchar(char c, FILE *stream)
{
	// UART 두 개에 다 메시지를 출력함
	tx0Char(c);
	tx1Char(c);
	return 0;
}

// UART0 을 이용한 출력
void tx0Char(char message)
{
	while (((UCSR0A>>UDRE0)&0x01) == 0) ;  // UDRE, data register empty
	UDR0 = message;
}

// UART1 을 이용한 출력
void tx1Char(char message)
{
	while (((UCSR1A>>UDRE1)&0x01) == 0) ;  // UDRE, data register empty
	UDR1 = message;
}

void port_init(void)
{		
	PORTA = 0x00;
	DDRA  = 0x00;
	PORTB = 0x00;
	DDRB  = 0x00;
	PORTC = 0x00; //m103 output only
	DDRC  = 0x00;
	PORTD = 0x00;
	DDRD  = 0x00;
	PORTE = 0x00;
	DDRE  = 0x00;
	PORTF = 0x00;
	DDRF  = 0x00;
	PORTG = 0x00;
	DDRG  = 0x00;
}

//UART0 initialize
// desired baud rate: 9600
// actual: baud rate:9615 (0.2%)
// char size: 8 bit
// parity: Disabled
void uart0_init(void)
{
	UCSR0B = 0x00; //disable while setting baud rate
	UCSR0A = 0x00;
	UCSR0C = 0x06;   // 0000_0110
	UBRR0L = 0x67; //set baud rate lo
	UBRR0H = 0x00; //set baud rate hi
	//UCSR0B = 0x18;  // 수신가능
	UCSR0B= (1<<RXEN0)|(1<<TXEN0)|(1<<RXCIE0);
	//UCSR0B = (1<<TXEN0);
	//UCSR0B = (1<<RXEN0);
}

// UART1 initialize
// desired baud rate:9600
// actual baud rate:9615 (0.2%)
// char size: 8 bit
// parity: Disabled
void uart1_init(void)
{
	UCSR1B = 0x00; //disable while setting baud rate
	UCSR1A = 0x00;
	UCSR1C = 0x06;
	// UBRR1L = 0x2F; //set baud rate lo 7.3728 MHz
	// UBRR1L = 0x47; //set baud rate lo 11.0592 Mhz
	UBRR1L = 0x67; //set baud rate lo 16Mhz
	UBRR1H = 0x00; //set baud rate hi
	UCSR1B = 0x18;
	//UCSR0B= (1<<RXEN0)|(1<<TXEN0)|(1<<RXCIE0);
}

//call this routine to initialize all peripherals
void init_devices(void)
{
	//stop errant interrupts until set up
	cli(); //disable all interrupts
	XMCRA = 0x00; //external memory
	XMCRB = 0x00; //external memory
	port_init();
	uart0_init();
	uart1_init();
	fdevopen(Putchar,0);
 
	MCUCR = 0x00;
	EICRA = 0x00; //extended ext ints
	EICRB = 0x00; //extended ext ints
	EIMSK = 0x00;
	TIMSK = 0x00; //timer interrupt sources
	ETIMSK = 0x00; //SREG 직접 설정 대신 모듈화 호출
	sei(); //re-enable interrupts
	//all peripherals are now initialized
}

// 시간 지연 함수
void delay_us(int time_us)
{
	register int i;
	for(i=0; i<time_us; i++){   // 4 cycle +
		asm("PUSH   R0");        // 2 cycle +
		asm("POP    R0");        // 2 cycle +
		asm("PUSH   R0");        // 2 cycle +
		asm("POP    R0");        // 2 cycle +
		/* asm("PUSH   R0");        // 2 cycle +
		asm("POP    R0");        // 2 cycle   = 16 cycle = 1us for 16MHz*/
	}
}

void delay_ms(int time_ms)
{
	register int i;
	for(i=0;i<time_ms;i++) delay_us(1000);
}







/** Call nearly all wallet functions and make sure they
  * return #WALLET_NOT_LOADED somehow. This should only be called if a wallet
  * is not loaded. */
static void checkFunctionsReturnWalletNotLoaded(void)
{
	uint8_t temp[128];
	uint32_t check_num_addresses;
	AddressHandle ah;
	PointAffine public_key;

	// newWallet() not tested because it calls initWallet() when it's done.
	ah = makeNewAddress(temp, &public_key);
	if ((ah == BAD_ADDRESS_HANDLE) && (walletGetLastError() == WALLET_NOT_LOADED))
	{
		reportSuccess();
	}
	else
	{
		printf("makeNewAddress() doesn't recognise when wallet isn't loaded\n");
		reportFailure();
	}
	check_num_addresses = getNumAddresses();
	if ((check_num_addresses == 0) && (walletGetLastError() == WALLET_NOT_LOADED))
	{
		reportSuccess();
	}
	else
	{
		printf("getNumAddresses() doesn't recognise when wallet isn't loaded\n");
		reportFailure();
	}
	if (getAddressAndPublicKey(temp, &public_key, 0) == WALLET_NOT_LOADED)
	{
		reportSuccess();
	}
	else
	{
		printf("getAddressAndPublicKey() doesn't recognise when wallet isn't loaded\n");
		reportFailure();
	}
	if (getPrivateKey(temp, 0) == WALLET_NOT_LOADED)
	{
		reportSuccess();
	}
	else
	{
		printf("getPrivateKey() doesn't recognise when wallet isn't loaded\n");
		reportFailure();
	}
	if (changeEncryptionKey(temp, 0) == WALLET_NOT_LOADED)
	{
		reportSuccess();
	}
	else
	{
		printf("changeEncryptionKey() doesn't recognise when wallet isn't loaded\n");
		reportFailure();
	}
	if (changeWalletName(temp) == WALLET_NOT_LOADED)
	{
		reportSuccess();
	}
	else
	{
		printf("changeWalletName() doesn't recognise when wallet isn't loaded\n");
		reportFailure();
	}
	if (backupWallet(false, 0) == WALLET_NOT_LOADED)
	{
		reportSuccess();
	}
	else
	{
		printf("backupWallet() doesn't recognise when wallet isn't loaded\n");
		reportFailure();
	}
	if (getMasterPublicKey(&public_key, temp) == WALLET_NOT_LOADED)
	{
		reportSuccess();
	}
	else
	{
		printf("getMasterPublicKey() doesn't recognise when wallet isn't loaded\n");
		reportFailure();
	}
}

/** Call all wallet functions which accept a wallet number and check
  * that they fail or succeed for a given wallet number.
  * \param wallet_spec The wallet number to check.
  * \param should_succeed true if the wallet number is valid (and thus the
  *                       wallet functions should succeed), false if the wallet
  *                       number is not valid (and thus the wallet functions
  *                       should fail).
  */
static void checkWalletSpecFunctions(uint32_t wallet_spec, bool should_succeed)
{
	uint8_t wallet_uuid[UUID_LENGTH];
	uint8_t name[NAME_LENGTH];
	uint32_t version;
	WalletErrors wallet_return;

	memset(name, ' ', NAME_LENGTH);
	uninitWallet();
	wallet_return = newWallet(wallet_spec, name, false, NULL, false, NULL, 0);
	if (should_succeed && (wallet_return != WALLET_NO_ERROR))
	{
		printf("newWallet() failed with wallet number %u when it should have succeeded\n", wallet_spec);
		reportFailure();
	}
	else
	{
		reportSuccess();
	}
	if (!should_succeed && (wallet_return != WALLET_INVALID_WALLET_NUM))
	{
		printf("newWallet() did not return WALLET_INVALID_WALLET_NUM with wallet number %u when it should have\n", wallet_spec);
		reportFailure();
	}
	else
	{
		reportSuccess();
	}

	uninitWallet();
	// This call to initWallet() must be placed after the call to newWallet()
	// so that if should_succeed is true, there's a valid wallet in the
	// specified place.
	wallet_return = initWallet(wallet_spec, NULL, 0);
	if (should_succeed && (wallet_return != WALLET_NO_ERROR))
	{
		printf("initWallet() failed with wallet number %u when it should have succeeded\n", wallet_spec);
		reportFailure();
	}
	else
	{
		reportSuccess();
	}
	if (!should_succeed && (wallet_return != WALLET_INVALID_WALLET_NUM))
	{
		printf("initWallet() did not return WALLET_INVALID_WALLET_NUM with wallet number %u when it should have\n", wallet_spec);
		reportFailure();
	}
	else
	{
		reportSuccess();
	}

	uninitWallet();
	wallet_return = getWalletInfo(&version, name, wallet_uuid, wallet_spec);
	if (should_succeed && (wallet_return != WALLET_NO_ERROR))
	{
		printf("getWalletInfo() failed with wallet number %u when it should have succeeded\n", wallet_spec);
		reportFailure();
	}
	else
	{
		reportSuccess();
	}
	if (!should_succeed && (wallet_return != WALLET_INVALID_WALLET_NUM))
	{
		printf("getWalletInfo() did not return WALLET_INVALID_WALLET_NUM with wallet number %u when it should have\n", wallet_spec);
		reportFailure();
	}
	else
	{
		reportSuccess();
	}
}




const uint8_t test_password0[] = "1234";
const uint8_t test_password1[] = "ABCDEFGHJ!!!!";
const uint8_t new_test_password[] = "new password";
/** Entry point. This is the first thing which is called after startup code.
  * This never returns. */
int main(void)
{


	init_devices();
	//insert your functional code here...
	
	printf("testing...");
	delay_ms(1200);
	printf("$$CS\r");		// 화면 클리어

	delay_ms(2400);
	printf("$$L1\r");		// 백라이트 on
	delay_ms(1200);
	printf("$$BB\r");		// 커서 Blink
	delay_ms(1200);
	
	//processPacket();
	
 	uint8_t temp[128];
 	uint8_t address1[20];
 	uint8_t address2[20];
 	uint8_t compare_address[20];
 	uint8_t name[NAME_LENGTH];
 	uint8_t name2[NAME_LENGTH];
 	uint8_t compare_name[NAME_LENGTH];
 	uint8_t wallet_uuid[UUID_LENGTH];
 	uint8_t wallet_uuid2[UUID_LENGTH];
 	uint32_t version;
 	uint8_t seed1[SEED_LENGTH];
 	uint8_t seed2[SEED_LENGTH];
 	uint8_t encrypted_seed[SEED_LENGTH];
 	uint8_t chain_code[32];
 	struct WalletRecordUnencryptedStruct unencrypted_part;
 	struct WalletRecordUnencryptedStruct compare_unencrypted_part;
 	uint8_t *address_buffer;
 	uint8_t one_byte;
 	uint32_t start_address;
 	uint32_t end_address;
 	uint32_t version_field_address;
 	uint32_t returned_num_wallets;
 	uint32_t stupidly_calculated_num_wallets;
 	AddressHandle *handles_buffer;
 	AddressHandle ah;
 	PointAffine master_public_key;
 	PointAffine public_key;
 	PointAffine compare_public_key;
 	PointAffine *public_key_buffer;
 	bool abort;
 	bool is_zero;
 	bool abort_duplicate;
 	bool abort_error;
 	int i;
 	int j;
 	int version_field_counter;
 	bool found;
 	uint32_t histogram[256];
 	uint32_t histogram_count;
 	uint8_t copy_of_nv[TEST_GLOBAL_PARTITION_SIZE + TEST_ACCOUNTS_PARTITION_SIZE];
 	uint8_t copy_of_nv2[TEST_GLOBAL_PARTITION_SIZE + TEST_ACCOUNTS_PARTITION_SIZE];
 	uint8_t pool_state[ENTROPY_POOL_LENGTH];

 	initTests(__FILE__);

// 	initWalletTest();
 	initialiseDefaultEntropyPool();
 	suppress_set_entropy_pool = false;
 	// Blank out non-volatile storage area (set to all nulls).
 	temp[0] = 0;


	// Check that sanitiseEverything() is able to function with NV
	// storage in this state.
	minimum_address_written[PARTITION_GLOBAL] = 0xffffffff;
	maximum_address_written[PARTITION_GLOBAL] = 0;
	minimum_address_written[PARTITION_ACCOUNTS] = 0xffffffff;
	maximum_address_written[PARTITION_ACCOUNTS] = 0;
	if (sanitiseEverything() == WALLET_NO_ERROR)
	{
		reportSuccess();
	}
	else
	{
		printf("Cannot nuke NV storage using sanitiseEverything()\n");
		reportFailure();
	}

	// Check that sanitiseNonVolatileStorage() overwrote (almost) everything
	// with random data.
	memset(histogram, 0, sizeof(histogram));
	histogram_count = 0;
	//	fseek(wallet_test_file, 0, SEEK_SET);
	for (i = 0; i < (TEST_GLOBAL_PARTITION_SIZE + TEST_ACCOUNTS_PARTITION_SIZE); i++)
	{
//		fread(temp, 1, 1, wallet_test_file);
		histogram[temp[0]]++;
		histogram_count++;
	}
	// "Random data" here is defined as: no value appears more than 1/16 of the time.
	abort = false;
	for (i = 0; i < 256; i++)
	{
		if (histogram[i] > (histogram_count / 16))
		{
			printf("sanitiseNonVolatileStorage() causes %02x to appear improbably often\n", i);
			reportFailure();
			abort = true;
		}
	}
	if (!abort)
	{
		reportSuccess();
	}
	
	
	// Check that sanitiseEverything() overwrote everything.
	if ((minimum_address_written[PARTITION_GLOBAL] != 0)
	|| (maximum_address_written[PARTITION_GLOBAL] != (TEST_GLOBAL_PARTITION_SIZE - 1))
	|| (minimum_address_written[PARTITION_ACCOUNTS] != 0)
	|| (maximum_address_written[PARTITION_ACCOUNTS] != (TEST_ACCOUNTS_PARTITION_SIZE - 1)))
	{
		printf("sanitiseEverything() did not overwrite everything\n");
		reportFailure();
	}
	else
	{
		reportSuccess();
	}

	// Check that the version field is "wallet not there".
	if (getWalletInfo(&version, temp, wallet_uuid, 0) == WALLET_NO_ERROR)
	{
		reportSuccess();
	}
	else
	{
		printf("getWalletInfo() failed after sanitiseNonVolatileStorage() was called\n");
		reportFailure();
	}
	if (version == VERSION_NOTHING_THERE)
	{
		reportSuccess();
	}
	else
	{
		printf("sanitiseNonVolatileStorage() does not set version to nothing there\n");
		reportFailure();
	}

	// initWallet() hasn't been called yet, so nearly every function should
	// return WALLET_NOT_THERE somehow.
	checkFunctionsReturnWalletNotLoaded();

	// The non-volatile storage area was blanked out, so there shouldn't be a
	// (valid) wallet there.
	if (initWallet(0, NULL, 0) == WALLET_NOT_THERE)
	{
		reportSuccess();
	}
	else
	{
		printf("initWallet() doesn't recognise when wallet isn't there\n");
		reportFailure();
	}

	// Try creating a wallet and testing initWallet() on it.
	memcpy(name, "123456789012345678901234567890abcdefghij", NAME_LENGTH);
	if (newWallet(0, name, false, NULL, false, NULL, 0) == WALLET_NO_ERROR)
	{
		reportSuccess();
	}
	else
	{
		printf("Could not create new wallet\n");
		reportFailure();
	}
	if (initWallet(0, NULL, 0) == WALLET_NO_ERROR)
	{
		reportSuccess();
	}
	else
	{
		printf("initWallet() does not recognise new wallet\n");
		reportFailure();
	}
	if ((getNumAddresses() == 0) && (walletGetLastError() == WALLET_EMPTY))
	{
		reportSuccess();
	}
	else
	{
		printf("New wallet isn't empty\n");
		reportFailure();
	}

	// Check that the version field is "unencrypted wallet".
	if (getWalletInfo(&version, temp, wallet_uuid, 0) == WALLET_NO_ERROR)
	{
		reportSuccess();
	}
	else
	{
		printf("getWalletInfo() failed after newWallet() was called\n");
		reportFailure();
	}
	if (version == VERSION_UNENCRYPTED)
	{
		reportSuccess();
	}
	else
	{
		printf("newWallet() does not set version to unencrypted wallet\n");
		reportFailure();
	}

	// Check that sanitise_nv_wallet() deletes wallet.
	if (sanitiseEverything() == WALLET_NO_ERROR)
	{
		reportSuccess();
	}
	else
	{
		printf("Cannot nuke NV storage using sanitiseNonVolatileStorage()\n");
		reportFailure();
	}
	if (initWallet(0, NULL, 0) == WALLET_NOT_THERE)
	{
		reportSuccess();
	}
	else
	{
		printf("sanitiseEverything() isn't deleting wallet\n");
		reportFailure();
	}

	// Check that newWallet() works.
	if (newWallet(0, name, false, NULL, false, NULL, 0) == WALLET_NO_ERROR)
	{
		reportSuccess();
	}
	else
	{
		printf("newWallet() fails for recently sanitised NV storage\n");
		reportFailure();
	}
	if (makeNewAddress(temp, &public_key) != BAD_ADDRESS_HANDLE)
	{
		reportSuccess();
	}
	else
	{
		printf("Couldn't create new address in new wallet\n");
		reportFailure();
	}

	// newWallet() shouldn't overwrite an existing wallet.
	if (newWallet(0, name, false, NULL, false, NULL, 0) == WALLET_ALREADY_EXISTS)
	{
		reportSuccess();
	}
	else
	{
		printf("newWallet() overwrites existing wallet\n");
		reportFailure();
	}

/*	// Check that a deleteWallet()/newWallet() sequence does overwrite an
	// existing wallet.
	if (deleteWallet(0) == WALLET_NO_ERROR)
	{
		reportSuccess();
	}
	else
	{
		printf("deleteWallet() failed\n");
		reportFailure();
	}
	if (newWallet(0, name, false, NULL, false, NULL, 0) == WALLET_NO_ERROR)
	{
		reportSuccess();
	}
	else
	{
		printf("newWallet() fails for recently deleted wallet\n");
		reportFailure();
	}

	// Check that deleteWallet() deletes wallet.
	deleteWallet(0);
	newWallet(0, name, false, NULL, false, NULL, 0);
	if (initWallet(0, NULL, 0) == WALLET_NO_ERROR)
	{
		reportSuccess();
	}
	else
	{
		printf("initWallet() failed just after calling newWallet()\n");
		reportFailure();
	}
	deleteWallet(0);
	if (initWallet(0, NULL, 0) == WALLET_NOT_THERE)
	{
		reportSuccess();
	}
	else
	{
		printf("deleteWallet() isn't deleting wallet\n");
		reportFailure();
	}
*/
	
}


/** This will be called whenever something very unexpected occurs. This
  * function must not return. */
void fatalError(void)
{
	//streamError();
	cli();
	for (;;)
	{
		// do nothing
	}
}














