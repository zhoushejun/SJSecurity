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
    
    /// 注意事项，针对默认的算法，以下注释为官方资料：
    /// @constant kSecKeyAlgorithmRSAEncryptionPKCS1
    /// RSA encryption or decryption, data is padded using PKCS#1 padding scheme.
    /// This algorithm should be used only for backward compatibility with existing protocols and data.
    /// New implementations should choose cryptographically stronger algorithm instead (see kSecKeyAlgorithmRSAEncryptionOAEP).
    /// Input data must be at most "key block size - 11" bytes long and returned block has always the same size as block size, as returned by SecKeyGetBlockSize().
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
        let status = SecKeyGeneratePair(parameters as CFDictionary, &publicSecKey, &privateSecKey)
        assert(status == errSecSuccess, "Error For SecKeyGeneratePair: \(status)")
    }
    
    /// 加密，使用公钥加密
    /// - Parameter source: 需要加密的明文
    public func encrypt(source: Data) -> Data? {
        guard !source.isEmpty, let pubKey = self.publicSecKey, let _ = self.privateSecKey else {  return nil }
        guard let sourceData = source as CFData? else { return nil }
        var error: Unmanaged<CFError>?
        let encryptedData =  SecKeyCreateEncryptedData(pubKey, algorithm, sourceData, &error)
        if error != nil {
            print("res = \(error!.takeUnretainedValue().localizedDescription)")
            return nil
        }
        return encryptedData as Data?
    }
    
    /// 解密，使用私钥解密
    /// - Parameter source: 需要解密的密文
    public func decrypt(source: Data) -> Data? {
        guard !source.isEmpty, let priKey = self.privateSecKey, let _ = self.publicSecKey else { return nil }
        var error: Unmanaged<CFError>?
        let decryptedData =  SecKeyCreateDecryptedData(priKey, algorithm, source as CFData, &error) as Data?
        if error != nil {
            print("res = \(error!.takeUnretainedValue().localizedDescription)")
            return nil
        }
        return decryptedData
    }
}
