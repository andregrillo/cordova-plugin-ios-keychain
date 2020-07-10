/*
 Licensed to the Apache Software Foundation (ASF) under one
 or more contributor license agreements.  See the NOTICE file
 distributed with this work for additional information
 regarding copyright ownership.  The ASF licenses this file
 to you under the Apache License, Version 2.0 (the
 "License"); you may not use this file except in compliance
 with the License.  You may obtain a copy of the License at

 http://www.apache.org/licenses/LICENSE-2.0

 Unless required by applicable law or agreed to in writing,
 software distributed under the License is distributed on an
 "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 KIND, either express or implied.  See the License for the
 specific language governing permissions and limitations
 under the License.
 */

#import "CDVKeychain.h"
#import "A0SimpleKeychain.h"

@implementation CDVKeychain

- (void) get:(CDVInvokedUrlCommand*)command {
  [self.commandDelegate runInBackground:^{

    CDVPluginResult* pluginResult = nil;
      
      NSDictionary *keychainDict = [self dictionaryFromKeychainWithKey];
      
      NSString *value;
      
      if ([keychainDict[@"type"] isEqual:@"transfer"]) {
          value = [NSString stringWithFormat:@"%@,%@,%@",keychainDict[@"type"], keychainDict[@"amount"], keychainDict[@"payee"]];
      }
      else if ([keychainDict[@"type"] isEqual:@"request"]){
          value = [NSString stringWithFormat:@"%@,%@,%@",keychainDict[@"type"], keychainDict[@"amount"], keychainDict[@"payer"]];
      }
      else {
          value = @"Key not available";
      }

    pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK messageAsString:value];
    [self.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
  }];
}

- (void) set:(CDVInvokedUrlCommand*)command {
  [self.commandDelegate runInBackground:^{
    NSArray* arguments = command.arguments;
    CDVPluginResult* pluginResult = nil;

    if([arguments count] < 3) {
      pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_ERROR
      messageAsString:@"incorrect number of arguments for setWithTouchID"];
      [self.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
      return;
    }

    NSString* key = [arguments objectAtIndex:0];
    NSString* value = [arguments objectAtIndex:1];
    BOOL useTouchID = [[arguments objectAtIndex:2] boolValue];
   
    A0SimpleKeychain *keychain = [A0SimpleKeychain keychain];

    if(useTouchID) {
      keychain.useAccessControl = YES;
      keychain.defaultAccessiblity = A0SimpleKeychainItemAccessibleWhenPasscodeSetThisDeviceOnly;
    }

    [keychain setString:value forKey:key];

    pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK];
    [self.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
  }];
}

- (void) remove:(CDVInvokedUrlCommand*)command {
  [self.commandDelegate runInBackground:^{
    NSArray* arguments = command.arguments;
    CDVPluginResult* pluginResult = nil;

    if([arguments count] < 1) {
      pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_ERROR
      messageAsString:@"incorrect number of arguments for remove"];
      [self.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
      return;
    }

    NSString *key = [arguments objectAtIndex:0];

    A0SimpleKeychain *keychain = [A0SimpleKeychain keychain];
    [keychain deleteEntryForKey:key];

    pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK];
    [self.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
  }];
}

- (NSDictionary *)dictionaryFromKeychainWithKey {
    // setup keychain query properties
    NSDictionary *readQuery = @{
        (__bridge id)kSecAttrAccount: @"operation",
        (__bridge id)kSecReturnData: (id)kCFBooleanTrue,
        (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword
    };

    CFDataRef serializedDictionary = NULL;
    OSStatus status = SecItemCopyMatching ((__bridge CFDictionaryRef)readQuery, (CFTypeRef *)&serializedDictionary);
    if (status == noErr)
    {
        // deserialize dictionary
        NSData *data = (__bridge NSData *)serializedDictionary;
        NSDictionary *storedDictionary = [NSKeyedUnarchiver unarchiveObjectWithData:data];
        NSLog([NSString stringWithFormat:@"Conteudo da key: %@", storedDictionary]);
        return storedDictionary;
    }
    else
    {
        NSLog (@"%d %@", (int)status, @"Couldn't read from Keychain.");
        return nil;
    }
}

@end
