//
//  utility.h
//  secp256k1-lib
//
//  Created by Amit Shah on 2018-05-30.
//  Copyright © 2018 Amit Shah. All rights reserved.
//

#ifndef utility_h
#define utility_h



@interface Utility : NSObject {

}

+ (id)instance;
- (void) testSignature;
- (void) testSignatureVerification;
- (void) testSignatureVerification2;

@end

#endif /* utility_h */
