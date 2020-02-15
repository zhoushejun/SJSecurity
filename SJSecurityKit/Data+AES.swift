//
//  Data+AES.swift
//  SJSecurity
//
//  Created by 周社军 on 2020/2/15.
//  Copyright © 2020 周社军. All rights reserved.
//

import Foundation
import CommonCrypto

extension Data {
    private func aesCrypt(operation: CCOperation, algoritm:CCAlgorithm, key: Data, iv:Data? = nil) -> Data? {
        let keyData:NSData = key as NSData
        let data:NSData = self as NSData
        let buffer = NSMutableData(length:Int(data.length) + kCCBlockSizeAES128 )!
        let bufferSize = self.count + kCCBlockSizeAES128
        let options:CCOptions = UInt32(kCCOptionECBMode + kCCOptionPKCS7Padding)
        var encryptedBytes:size_t = 0
        
        let cryptStatus = CCCrypt(operation,
                                  algoritm,
                                  options,
                                  keyData.bytes, key.count,
                                  (iv as NSData?)?.bytes,
                                  data.bytes, self.count,
                                  buffer.mutableBytes, bufferSize,
                                  &encryptedBytes)
        
        if UInt32(cryptStatus) == UInt32(kCCSuccess){
            buffer.length = Int(encryptedBytes)
        } else {
            return nil
        }
        let resultData = NSData.init(bytes: buffer.mutableBytes, length: encryptedBytes)
        return resultData as Data
    }
    
    public func aesCBCEncrypt(key: Data, iv:Data) -> Data? {
        return aesCrypt(operation: CCOperation(kCCEncrypt), algoritm: CCAlgorithm(kCCAlgorithmAES), key: key, iv: iv)
    }
    
    public func aesCBCDecrypt(key: Data, iv:Data) -> Data? {
        return aesCrypt(operation: CCOperation(kCCDecrypt), algoritm: CCAlgorithm(kCCAlgorithmAES), key: key, iv: iv)
    }
    
    public func aesECBEncrypt(key: Data) -> Data? {
        return aesCrypt(operation: CCOperation(kCCEncrypt), algoritm: CCAlgorithm(kCCAlgorithmAES), key: key, iv: nil)
    }
    
    public func aesECBDecrypt(key: Data) -> Data? {
        return aesCrypt(operation: CCOperation(kCCDecrypt), algoritm: CCAlgorithm(kCCAlgorithmAES), key: key, iv: nil)
    }
}
