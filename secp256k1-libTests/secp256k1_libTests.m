//
//  secp256k1_libTests.m
//  secp256k1-libTests
//
//  Created by Amit Shah on 2018-05-30.
//  Copyright © 2018 Amit Shah. All rights reserved.
//

#import <XCTest/XCTest.h>
#import "utility.h"

@interface secp256k1_libTests : XCTestCase

@end

@implementation secp256k1_libTests{
    Utility *util;
}

- (void)setUp {
    [super setUp];
    util = [Utility instance];
    // Put setup code here. This method is called before the invocation of each test method in the class.
}

- (void)tearDown {
    // Put teardown code here. This method is called after the invocation of each test method in the class.
    [super tearDown];
}

- (void)testExample {
    [util testSignature];
    [util testSignatureVerification];
    [util testSignatureVerification2];
    // This is an example of a functional test case.
    // Use XCTAssert and related functions to verify your tests produce the correct results.
}

- (void)testHash {
    NSString* hashedData = [util keccak256:@"68656c6c6f"];
    NSLog(hashedData);
    XCTAssertTrue([hashedData isEqualToString:@"1c8aff950685c2ed4bc3174f3472287b56d9517b9c948127319a09a7a36deac8"]);
}

- (void) testSign{
    NSString* signature = [util ecsign:@"68656c6c6f" withKey:@"e331b6d69882b4cb4ea581d88e0b604039a3de5967688d3dcffdd2270c0fd109"];
    XCTAssertTrue([signature isEqualToString:@"e6a21b8c7e3ae24f7486f3ee2d5e1aaa1d47f0b5efca149bf141d2fd7494f06805944d0564e8fdcb35b2b91fd154d8fa78dc485dc8f40f1b1b5bf9d0f14d77a900"]);
}

- (void) testVerify{
    NSString* address =[util ecrecover:@"b0312ee1e07860ab62a4df71d1dd03567911899f548de970e474d3f0dc2c3403" withR:@"759b84d432f0feb92eac6c23cd9433aa4730e678ae5857a28167256b47fe841f"
              withS:@"5e43c02c7f385599a934a07b3f62ee642634d5d3f19909dbd244ef662df6a718"
              withV:28];
    XCTAssertTrue([address isEqualToString:@"be862ad9abfe6f22bcb087716c7d89a26051f74c"]);
}
- (void)testPerformanceExample {
    // This is an example of a performance test case.
    [self measureBlock:^{
        // Put the code you want to measure the time of here.
    }];
}

@end
