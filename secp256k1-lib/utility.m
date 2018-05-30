//
//  secp25k1_lib.m
//  secp256k1-lib
//
//  Created by Amit Shah on 2018-05-30.
//  Copyright © 2018 Amit Shah. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "utility.h"


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
    
    NSLog([NSString hexStringWithData:r ofLength:32]);
    NSLog([NSString hexStringWithData:s ofLength:32]);
    NSLog(@"%d",(uint8_t)recoverable_sig.data[64]);
   
    
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
