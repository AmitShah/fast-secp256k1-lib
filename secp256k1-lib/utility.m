//
//  secp25k1_lib.m
//  secp256k1-lib
//
//  Created by Amit Shah on 2018-05-30.
//  Copyright © 2018 Amit Shah. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "utility.h"
#import "secp256k1.h"
#import "secp256k1_ecdh.h"
#import "secp256k1_recovery.h"
#import "util.h"
#import "hash_impl.h"
#import "keccak-tiny.h"

static int custom_nonce_function_rfc6979(unsigned char *nonce32, const unsigned char *msg32, const unsigned char *key32, const unsigned char *algo16, void *data, unsigned int counter){
    return secp256k1_nonce_function_rfc6979(nonce32, msg32, key32, algo16, data, counter);
}

static NSData *stripDataZeros(NSData *data) {
    const char *bytes = data.bytes;
    NSUInteger offset = 0;
    while (offset < data.length && bytes[offset] == 0) { offset++; }
    return [data subdataWithRange:NSMakeRange(offset, data.length - offset)];
}

//hexBytes expect utf8strin encoded bytes within byte boundary
static NSData * dataFromChar(const char * chars, int len){
    
    int i = 0;
    bool flag = false;
    if(len > 1 && len %2!=0){
        flag = true;
    }
    NSMutableData *data = [NSMutableData dataWithCapacity:len / 2];
    char byteChars[3] = {'\0','\0','\0'};
    unsigned long wholeByte;
    
    while (i < len) {
        if(flag){
            byteChars[0] = '0';
            byteChars[1] = chars[i++];
            wholeByte = strtoul(byteChars, NULL, 16);
            [data appendBytes:&wholeByte length:1];
            flag = false;
        }
        else{
            byteChars[0] = chars[i++];
            byteChars[1] = chars[i++];
            wholeByte = strtoul(byteChars, NULL, 16);
            [data appendBytes:&wholeByte length:1];
        }
    }
    //unsigned char *bytePtr = (unsigned char *)[data bytes];
    return data;
    
}

static int secp256k1_der_read_len(const unsigned char **sigp, const unsigned char *sigend) {
    int lenleft, b1;
    size_t ret = 0;
    if (*sigp >= sigend) {
        return -1;
    }
    b1 = *((*sigp)++);
    if (b1 == 0xFF) {
        /* X.690-0207 8.1.3.5.c the value 0xFF shall not be used. */
        return -1;
    }
    if ((b1 & 0x80) == 0) {
        /* X.690-0207 8.1.3.4 short form length octets */
        return b1;
    }
    if (b1 == 0x80) {
        /* Indefinite length is not allowed in DER. */
        return -1;
    }
    /* X.690-207 8.1.3.5 long form length octets */
    lenleft = b1 & 0x7F;
    if (lenleft > sigend - *sigp) {
        return -1;
    }
    if (**sigp == 0) {
        /* Not the shortest possible length encoding. */
        return -1;
    }
    if ((size_t)lenleft > sizeof(size_t)) {
        /* The resulting length would exceed the range of a size_t, so
         * certainly longer than the passed array size.
         */
        return -1;
    }
    while (lenleft > 0) {
        ret = (ret << 8) | **sigp;
        if (ret + lenleft > (size_t)(sigend - *sigp)) {
            /* Result exceeds the length of the passed array. */
            return -1;
        }
        (*sigp)++;
        lenleft--;
    }
    if (ret < 128) {
        /* Not the shortest possible length encoding. */
        return -1;
    }
    return ret;
}

static int secp256k1_der_parse_integer(char *r, const unsigned char **sig, const unsigned char *sigend) {
    int overflow = 0;
    unsigned char ra[32] = {0};
    int rlen;
    
    if (*sig == sigend || **sig != 0x02) {
        /* Not a primitive integer (X.690-0207 8.3.1). */
        return 0;
    }
    (*sig)++;
    rlen = secp256k1_der_read_len(sig, sigend);
    if (rlen <= 0 || (*sig) + rlen > sigend) {
        /* Exceeds bounds or not at least length 1 (X.690-0207 8.3.1).  */
        return 0;
    }
    if (**sig == 0x00 && rlen > 1 && (((*sig)[1]) & 0x80) == 0x00) {
        /* Excessive 0x00 padding. */
        return 0;
    }
    if (**sig == 0xFF && rlen > 1 && (((*sig)[1]) & 0x80) == 0x80) {
        /* Excessive 0xFF padding. */
        return 0;
    }
    if ((**sig & 0x80) == 0x80) {
        /* Negative. */
        overflow = 1;
    }
    while (rlen > 0 && **sig == 0) {
        /* Skip leading zero bytes */
        rlen--;
        (*sig)++;
    }
    if (rlen > 32) {
        overflow = 1;
    }
    if (!overflow) {
        memcpy(ra + 32 - rlen, *sig, rlen);
        
        //secp256k1_scalar_set_b32(r, ra, &overflow);
    }
    if (overflow) {
        //secp256k1_scalar_set_int(r, 0);
    }
    (*sig) += rlen;
    
    memcpy(r,ra,rlen);
    return 1;
}

static int der_sig_parse(char *rr, char *rs, const unsigned char *sig, size_t size) {
    const unsigned char *sigend = sig + size;
    int rlen;
    if (sig == sigend || *(sig++) != 0x30) {
        /* The encoding doesn't start with a constructed sequence (X.690-0207 8.9.1). */
        return 0;
    }
    rlen = secp256k1_der_read_len(&sig, sigend);
    if (rlen < 0 || sig + rlen > sigend) {
        /* Tuple exceeds bounds */
        return 0;
    }
    if (sig + rlen != sigend) {
        /* Garbage after tuple. */
        return 0;
    }
    
    if (!secp256k1_der_parse_integer(rr, &sig, sigend)) {
        return 0;
    }
    if (!secp256k1_der_parse_integer(rs, &sig, sigend)) {
        return 0;
    }
    
    if (sig != sigend) {
        /* Trailing garbage inside tuple. */
        return 0;
    }
    
    return 1;
}

@implementation NSData (NSData_hexadecimalString)

- (NSString *)hexString {
    const unsigned char *dataBuffer = (const unsigned char *)[self bytes];
    if (!dataBuffer) return [NSString string];
    
    NSUInteger          dataLength  = [self length];
    NSMutableString     *hexString  = [NSMutableString stringWithCapacity:(dataLength * 2)];
    
    for (int i = 0; i < dataLength; ++i)
        [hexString appendString:[NSString stringWithFormat:@"%02lx", (unsigned long)dataBuffer[i]]];
    
    return [NSString stringWithString:hexString];
}

@end

@implementation NSString (Hex)

+ (NSString*) hexStringWithData: (unsigned char*) data ofLength: (NSUInteger) len
{
    NSMutableString *tmp = [NSMutableString string];
    for (NSUInteger i=0; i<len; i++)
        [tmp appendFormat:@"%02x", data[i]];
    return [NSString stringWithString:tmp];
}

- (NSData *)dataFromHexString {
    return dataFromChar([self UTF8String],(int)[self length]  );
}


@end

@implementation Utility{
    secp256k1_context * ctx;
    unsigned char key[32];
}
    
+(id)instance {
    static Utility *instance = nil;
//        static dispatch_once_t onceToken;
//        dispatch_once(&onceToken, ^{
//            instance = [[self alloc] init];
//        });
    @synchronized(self) {
        if (instance == nil)
            instance = [[self alloc] init];
    }
    return instance;
}
    
- (id)init {
        if (self = [super init]) {
            ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
            memcpy(key,[@"e331b6d69882b4cb4ea581d88e0b604039a3de5967688d3dcffdd2270c0fd109" dataFromHexString].bytes,
                   32);
            //someProperty = [[NSString alloc] initWithString:@"Default Property Value"];
        }
        return self;
}

-(void) destroyContext{
     secp256k1_context_destroy(ctx);
}

- (void)dealloc {
     secp256k1_context_destroy(ctx);
        // Should never be called, but just here for clarity really.
}

-(NSString*) keccak256:(NSString *)dataHex{
    NSData * _data = [dataHex dataFromHexString];
    char hashedData[32];
    keccack_256(hashedData,32, [_data bytes], [_data length]);
    return [NSString hexStringWithData:hashedData ofLength:32];
}

-(NSString*) ecsign:(NSString*) hexData withKey:(NSString*) privateKey{
    
    NSData * _data = [hexData dataFromHexString];
    char hashedData[32];
    keccack_256(hashedData,32, [_data bytes], [_data length]);
    secp256k1_ecdsa_signature signature;
    unsigned char sig[74];
    size_t siglen = 74;
    secp256k1_ecdsa_recoverable_signature recoverable_sig;
    
    secp256k1_ecdsa_sign_recoverable(ctx, &recoverable_sig, hashedData, key, custom_nonce_function_rfc6979, NULL);
    
    
    secp256k1_ecdsa_recoverable_signature_convert(ctx,
                                                  &signature,
                                                  &recoverable_sig);
    
    secp256k1_ecdsa_signature_serialize_der(ctx, sig, &siglen, &signature);
    uint8_t r[32];
    uint8_t s[32];
    
    der_sig_parse(r,s, sig, siglen);
    
    uint8_t result[65];
    memcpy(result, r, 32);
    memcpy(result+32, s, 32);
    memcpy(result+64, &(recoverable_sig.data[64]), 1);
    return [NSString hexStringWithData:result ofLength:65];

}

-(NSString*) ecrecover:(NSString*) hexData withR:(NSString*) r withS:(NSString*)s withV:(int) v{
    secp256k1_ecdsa_recoverable_signature signature;
    secp256k1_pubkey pubkey;
    char hash[32];
    memcpy(hash, [hexData dataFromHexString].bytes,32);
    //int v = 27; //must be set correctly between 0 and 3
    char sig[64]; //r and s appended (32 bytes each)
    memcpy(sig,[ [r stringByAppendingString: s] dataFromHexString].bytes,
           64);
    
    secp256k1_ecdsa_recoverable_signature_parse_compact(ctx,&signature,
                                                        &sig,v-27);
    secp256k1_ecdsa_recover(ctx,&pubkey,&signature,hash);
    
    size_t output_size = 65;
    unsigned char output[65];
    
    secp256k1_ec_pubkey_serialize(ctx,
                                  output,
                                  &output_size,
                                  &pubkey,
                                  SECP256K1_EC_UNCOMPRESSED
                                  );
    
    char address[32];
    uint8_t ss[64];
    memcpy(ss, output+1,64);
    
    keccack_256(address, 32,ss, 64);
    
    
    NSString * stringAddress = [[NSString hexStringWithData:address ofLength:32] substringFromIndex:24];
    return stringAddress;
//    NSLog(stringAddress);
//    if([stringAddress isEqualToString:@"be862ad9abfe6f22bcb087716c7d89a26051f74c"]){
//        NSLog(@"recovered address (remove first 24 characters):%@",stringAddress);
//    }
    
}

//-(NSString*) sign:(NSString *)msg withKey:(NSString *)privateKey{
//    char data[msg.length];
//    char hashedData[32];
//    //char* data;
//    memcpy(data, [msg dataFromHexString].bytes,msg.length);
//    keccack_256(hashedData,32, data, msg.length);
//
//    char key[64];
//    memcpy(key,[privateKey dataFromHexString].bytes,
//           64);
//
//
//
//}

-(void) testSignature{
   
    
    char* elem = [[NSString stringWithFormat:@"element"] UTF8String];
    char hashedTransaction[32];
    keccack_256(hashedTransaction, 32, elem , 7);
    NSLog(@"hashed tx: %@", [NSString hexStringWithData:hashedTransaction ofLength:32]);
    secp256k1_ecdsa_signature signature;
    unsigned char sig[74];
    size_t siglen = 74;
    secp256k1_ecdsa_recoverable_signature recoverable_sig;
    
    secp256k1_ecdsa_sign_recoverable(ctx, &recoverable_sig, hashedTransaction, key, custom_nonce_function_rfc6979, NULL);
    
    
    secp256k1_ecdsa_recoverable_signature_convert(ctx,
                                                  &signature,
                                                  &recoverable_sig);
    
    //secp256k1_ecdsa_signature_recoverable_serialize_der(ctx, sig, &siglen, &signature);
    //secp256k1_ecdsa_sign(ctx, &signature, hashedTransaction, key, custom_nonce_function_rfc6979, NULL);
    secp256k1_ecdsa_signature_serialize_der(ctx, sig, &siglen, &signature);
    uint8_t r[32];
    uint8_t s[32];
    
    der_sig_parse(r,s, sig, siglen);
    //t.s = s;
    //t.r = r;
    
    uint8_t result[65];
    memcpy(result, r, 32);
    memcpy(result+32, s, 32);
    memcpy(result+64, &(recoverable_sig.data[64]), 1);
    NSLog([NSString hexStringWithData:result ofLength:65]);
    
    NSLog([NSString hexStringWithData:r ofLength:32]);
    NSLog([NSString hexStringWithData:s ofLength:32]);
    NSLog([NSString stringWithFormat: @"%d",(uint8_t)recoverable_sig.data[64]]);

   
    
}

-(void) testSignatureVerification{
    
    secp256k1_ecdsa_recoverable_signature signature;
    secp256k1_pubkey pubkey;
    char msg[32];
    memcpy(msg, [@"b0d7c4f82e2bde4dd554bcfd9ea6ac1b1ee361ee8b50db9096a481cd29dad207" dataFromHexString].bytes,32);
    int v = 27; //must be set correctly between 0 and 3
    char sig[64]; //r and s appended (32 bytes each)
    memcpy(sig,[@"9ecf61a6692cae53f6ad4e8c77c17b38638339124992bfbf7764b24a3c1ab7a87be4a70eba2af15a8376856330536e42c998bb89809b55bbc9cad7e73bc4fba8" dataFromHexString].bytes,
           64);
    
    secp256k1_ecdsa_recoverable_signature_parse_compact(ctx,&signature,
                                                        &sig,v-27);
    secp256k1_ecdsa_recover(ctx,&pubkey,&signature,msg);
    
    size_t output_size = 65;
    unsigned char output[65];
    
    secp256k1_ec_pubkey_serialize(ctx,
                                  output,
                                  &output_size,
                                  &pubkey,
                                  SECP256K1_EC_UNCOMPRESSED
                                  );
    
    char address[32];
    uint8_t ss[64];
    memcpy(ss, output+1,64);
    
    keccack_256(address, 32,ss, 64);
    
    
    NSString * stringAddress = [[NSString hexStringWithData:address ofLength:32] substringFromIndex:24];
    NSLog(stringAddress);
    if([stringAddress isEqualToString:@"be862ad9abfe6f22bcb087716c7d89a26051f74c"]){
        NSLog(@"recovered address (remove first 24 characters):%@",stringAddress);
    }
}


-(void) testSignatureVerification2{
    NSDate *methodStart = [NSDate date];
    for (int i = 0; i < 1000; i++){
        char* elem = [[NSString stringWithFormat:@"element"] UTF8String];
        
        char hashedTransaction[32];
        keccack_256(hashedTransaction, 32, elem , 7);
        
        secp256k1_ecdsa_recoverable_signature signature;
        secp256k1_pubkey pubkey;
        //        char msg[32];
        //        memcpy(msg, [@"b0312ee1e07860ab62a4df71d1dd03567911899f548de970e474d3f0dc2c3403" dataFromHexString].bytes,32);
        int v = 28; //must be set correctly between 0 and 3
        char sig[64]; //r and s appended (32 bytes each)
        memcpy(sig,[@"759b84d432f0feb92eac6c23cd9433aa4730e678ae5857a28167256b47fe841f5e43c02c7f385599a934a07b3f62ee642634d5d3f19909dbd244ef662df6a718" dataFromHexString].bytes,
               64);
        
        secp256k1_ecdsa_recoverable_signature_parse_compact(ctx,&signature,
                                                            &sig,v-27);
        secp256k1_ecdsa_recover(ctx,&pubkey,&signature,hashedTransaction);
        
        size_t output_size = 65;
        unsigned char output[65];
        
        secp256k1_ec_pubkey_serialize(ctx,
                                      output,
                                      &output_size,
                                      &pubkey,
                                      SECP256K1_EC_UNCOMPRESSED
                                      );
        
        char address[32];
        uint8_t ss[64];
        memcpy(ss, output+1,64);
        
        keccack_256(address, 32,ss, 64);
        
        
        NSString * stringAddress = [[NSString hexStringWithData:address ofLength:32] substringFromIndex:24];
        //NSLog(stringAddress);
        if([stringAddress isEqualToString:@"be862ad9abfe6f22bcb087716c7d89a26051f74c"]){
            //NSLog(@"recovered address (remove first 24 characters):%@",stringAddress);
        }
    }
    NSDate *methodFinish = [NSDate date];
    NSTimeInterval executionTime = [methodFinish timeIntervalSinceDate:methodStart];
    NSLog(@"executionTime = %f", executionTime);
    
}

@end
