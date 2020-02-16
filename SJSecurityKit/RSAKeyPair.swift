//
//  RSAKeyPair.swift
//  SJSecurity
//
//  Created by 周社军 on 2020/2/16.
//  Copyright © 2020 周社军. All rights reserved.
//

import Foundation
import Security

//官方资料：RSA keys may have key size values of 512, 768, 1024, or 2048.
public enum RSAKeySize: Int {
    case bits512 = 512
    case bits768 = 768
    case bits1024 = 1024
    case bits2048 = 2048
}

public class RSAKeyPair: NSObject {
    private(set) var publicSecKey: SecKey?
    private(set) var privateSecKey: SecKey?
    private var algorithm: SecKeyAlgorithm = .rsaEncryptionPKCS1
    
    init(algorithm: SecKeyAlgorithm = .rsaEncryptionPKCS1) {
        self.algorithm = algorithm
    }
    
    /// 生成RSA密钥对
    /// - Parameters:
    ///   - keySize: RSA键的长度，默认为：1024 bit
    ///   - algorithm: SecKey 使用的算法，默认为：rsaEncryptionPKCS1
    public class func generate(keySize: RSAKeySize = .bits1024, algorithm: SecKeyAlgorithm = .rsaEncryptionPKCS1) -> RSAKeyPair? {
        let keyPair = RSAKeyPair.init(algorithm: algorithm)
        keyPair.generate(keySize: keySize)
        return keyPair
    }
    
    /// 生成RSA密钥对
    /// - Parameter keySize: RSA键的长度
    public func generate(keySize: RSAKeySize = .bits1024) {
        let kSize = keySize.rawValue
        publicSecKey = nil
        privateSecKey = nil
        let parameters = [kSecAttrKeyType: kSecAttrKeyTypeRSA,
                          kSecAttrKeySizeInBits: kSize] as [CFString : Any]
        let ret = SecKeyGeneratePair(parameters as CFDictionary, &publicSecKey, &privateSecKey)
        assert(ret == errSecSuccess, "Error For SecKeyGeneratePair: \(ret)")
    }
    
    /// 加密，使用公钥加密
    /// - Parameter source: 需要加密的明文
    public func encrypt(source: String) -> String? {
        guard !source.isEmpty, let pubKey = self.publicSecKey, let _ = self.privateSecKey else {  return nil }
        guard let sourceData: CFData = source.data(using: .utf8) as CFData? else { return nil }
        
        var error: Unmanaged<CFError>?
        let encryptedData =  SecKeyCreateEncryptedData(pubKey, algorithm, sourceData, &error)
        if error != nil {
            print("res = \(error!.takeUnretainedValue().localizedDescription)")
            return nil
        }
        guard let retData = encryptedData as Data? else { return nil}
        return retData.base64EncodedString(options: .lineLength64Characters)
    }
    
    /// 解密，使用私钥解密
    /// - Parameter source: 需要解密的密文
    public func decrypt(source: String) -> String? {
        guard !source.isEmpty, let priKey = self.privateSecKey, let _ = self.publicSecKey else { return nil }
        guard let data: Data = Data.init(base64Encoded: source, options: .ignoreUnknownCharacters) else { return nil }
        
        var error: Unmanaged<CFError>?
        let decryptedData =  SecKeyCreateDecryptedData(priKey, algorithm, data as CFData, &error) as Data?
        if error != nil {
            print("res = \(error!.takeUnretainedValue().localizedDescription)")
            return nil
        }
        guard let resData = decryptedData else { return nil}
        return String.init(data: resData, encoding: .utf8)
    }
}
