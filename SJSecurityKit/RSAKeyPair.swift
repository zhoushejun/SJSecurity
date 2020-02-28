//
//  RSAKeyPair.swift
//  SJSecurity
//
//  Created by 周社军 on 2020/2/16.
//  Copyright © 2020 周社军. All rights reserved.
//

import Foundation
import Security

/// RSA键的长度，加密密钥中的 bit 位数。
/// 官方资料：RSA keys may have key size values of 512, 768, 1024, or 2048.
public enum RSAKeySize: Int {
    case bits512 = 512
    case bits768 = 768
    case bits1024 = 1024
    case bits2048 = 2048
}

public class RSAKeyPair: NSObject {
    // - MARK: ======================= 生成RSA密钥对 =======================
    
    private(set) var publicSecKey: SecKey?
    private(set) var privateSecKey: SecKey?
     
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
    
    /// 从 der 编码格式证书中读取公钥
    /// - Parameter cerFilePath: 证书目录
    public func readPublicSecKey(derFilePath: String) {
        guard let derData = try? NSData.init(contentsOfFile: derFilePath) as CFData,
            let certificate = SecCertificateCreateWithData(nil, derData) else {
                return
        }
        let policy = SecPolicyCreateBasicX509()
        var trust:SecTrust? = nil
        let status = SecTrustCreateWithCertificates(certificate, policy, &trust)
        assert(status == errSecSuccess, "SecTrustCreateWithCertificates error")
        publicSecKey = SecTrustCopyPublicKey(trust!)
    }
    
    /// 从 pem 编码格式证书中读取公钥
    /// - Parameters:
    ///   - pemFilePath: 证书目录
    ///   - keySize: RSA键的长度
    public func readPublicSecKey(pemFilePath: String, keySize: RSAKeySize = .bits1024) {
        guard let pemStr = try? String.init(contentsOfFile: pemFilePath, encoding: .ascii) else {
            return
        }
        var pemContent = pemStr.replacingOccurrences(of: "-----BEGIN PUBLIC KEY-----", with: "")
        pemContent = pemContent.replacingOccurrences(of: "\r", with: "")
        pemContent = pemContent.replacingOccurrences(of: "\n", with: "")
        pemContent = pemContent.replacingOccurrences(of: "-----END PUBLIC KEY-----", with: "")
        guard let pemData = Data.init(base64Encoded: pemContent) else {
            return
        }
        let pubKeyData = pemData as CFData
        let attributes = [kSecAttrKeyType: kSecAttrKeyTypeRSA,
                          kSecAttrKeyClass: kSecAttrKeyClassPublic,
                          kSecAttrKeySizeInBits: keySize] as [CFString : Any]
        var error: Unmanaged<CFError>?
        publicSecKey = SecKeyCreateWithData(pubKeyData, attributes as CFDictionary, &error)
        if error != nil {
            print("publicSecKey SecKeyCreateWithData error: \(error!.takeUnretainedValue().localizedDescription)")
        }
    }
    
    /// 从 pem 编码格式证书中读取私钥
    /// - Parameters:
    ///   - pemFilePath: 证书目录
    ///   - keySize: 加密密钥中的 bit 位数
    public func readPrivateSecKey(pemFilePath: String, keySize: RSAKeySize = .bits1024) {
        guard let pemStr = try? String.init(contentsOfFile: pemFilePath, encoding: .ascii) else {
            return
        }
        var pemContent = pemStr.replacingOccurrences(of: "-----BEGIN RSA PRIVATE KEY-----", with: "")
        pemContent = pemContent.replacingOccurrences(of: "\r", with: "")
        pemContent = pemContent.replacingOccurrences(of: "\n", with: "")
        pemContent = pemContent.replacingOccurrences(of: "-----END RSA PRIVATE KEY-----", with: "")
        guard let pemData = Data.init(base64Encoded: pemContent) else {
            return
        }
        let priKeyData = pemData as CFData
        let attributes = [kSecAttrKeyType: kSecAttrKeyTypeRSA,
                          kSecAttrKeyClass: kSecAttrKeyClassPrivate,
                          kSecAttrKeySizeInBits: keySize] as [CFString : Any]
        var error: Unmanaged<CFError>?
        privateSecKey = SecKeyCreateWithData(priKeyData, attributes as CFDictionary, &error)
        if error != nil {
            print("privateSecKey SecKeyCreateWithData error: \(error!.takeUnretainedValue().localizedDescription)")
        }
    }
    
    /// 从 p12 证书中读取公私钥
    /// - Parameters:
    ///   - p12FilePath: 证书目录
    ///   - password: 私钥密码，p12 证书一般都是要设置密码的
    public func readP12SecKeys(p12FilePath: String, password: String) {
        guard let pkcs12Data = try? NSData.init(contentsOfFile: p12FilePath) as CFData else {
            return
        }
        var imported: CFArray? = nil
        let passphrase = kSecImportExportPassphrase as String
        let options: Dictionary = [passphrase: password]
        var status = SecPKCS12Import(pkcs12Data, options as CFDictionary, &imported)
        assert(status == errSecSuccess, "SecPKCS12Import error status:\(status)")
        let importedItem = unsafeBitCast(CFArrayGetValueAtIndex(imported, 0), to: CFDictionary.self)
        guard let dic = importedItem as? Dictionary<String, Any> else {
            return
        }
        let identity = dic[kSecImportItemIdentity as String]  as! SecIdentity
        status = SecIdentityCopyPrivateKey(identity, &privateSecKey)
        assert(status == errSecSuccess, "SecIdentityCopyPrivateKey error status:\(status)")
        
        var certificate: SecCertificate?
        status = SecIdentityCopyCertificate(identity, &certificate)
        assert(status == errSecSuccess, "SecIdentityCopyCertificate error status:\(status)")
        let policy = SecPolicyCreateBasicX509()
        var trust:SecTrust? = nil
        status = SecTrustCreateWithCertificates(certificate!, policy, &trust)
        assert(status == errSecSuccess, "SecTrustCreateWithCertificates error")
        publicSecKey = SecTrustCopyPublicKey(trust!)
    }
    
    // - MARK: ======================= 公私钥加解密 =======================
    
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
    
    /// 生成RSA密钥对：公私钥加解密
    /// - Parameters:
    ///   - keySize: RSA键的长度，默认为：1024 bit
    ///   - algorithm: SecKey 使用的算法，默认为：rsaEncryptionPKCS1
    public class func generate(keySize: RSAKeySize = .bits1024, algorithm: SecKeyAlgorithm = .rsaEncryptionPKCS1) -> RSAKeyPair? {
        let keyPair = RSAKeyPair.init(algorithm: algorithm)
        keyPair.generate(keySize: keySize)
        return keyPair
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
//        另一种加密函数
//        guard !source.isEmpty, let pubKey = self.publicSecKey, let _ = self.privateSecKey else {  return nil }
//        guard let sourceData: NSData = source as CFData? else { return nil }
//
//        var blockSize =  SecKeyGetBlockSize(pubKey)
//        var outBuffer = [UInt8](repeating: 0, count: blockSize)
//        var outBufLen:Int = blockSize
//
//        let status = SecKeyEncrypt(pubKey, .OAEP, sourceData.bytes.assumingMemoryBound(to: UInt8.self), sourceData.length, &outBuffer, &outBufLen)
//        assert(status == errSecSuccess, "Error For SecKeyEncrypt: \(status)")
//
//        return Data.init(bytes: outBuffer, count: outBufLen)
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
    
    // - MARK: ======================= 签名与验签 =======================
    
    private var padding: SecPadding = .PKCS1
    
    init(padding: SecPadding = .PKCS1) {
        self.padding = padding
    }
    
    /// 生成RSA密钥对：签名与验签
    /// - Parameters:
    ///   - keySize: RSA键的长度，默认为：1024 bit
    ///   - algorithm: SecKey 使用的算法，默认为：rsaEncryptionPKCS1
    public class func generate(keySize: RSAKeySize = .bits1024, padding: SecPadding = .PKCS1) -> RSAKeyPair? {
        let keyPair = RSAKeyPair.init(padding: padding)
        keyPair.generate(keySize: keySize)
        return keyPair
    }
    
    /// 签名：给定要签名的私钥和数据，生成数字签名。
    /// - Parameter source: 待签名的数据，通常是明文数据的哈希值。
    /// return 签名后的数据
    /// 使用同一对公私钥对同一字符串进行签名，每次执行结果都是一样的。因为没有加随机数。
    /// 正常来说是要加一个随机数的，待完善。。。
    public func sign(source: Data) -> Data? {
        guard !source.isEmpty, let priKey = self.privateSecKey, let _ = self.publicSecKey else {  return nil }
        guard let sourceData: NSData = source as NSData? else { return nil }
        
        let sourceBuffer = sourceData.bytes.assumingMemoryBound(to: UInt8.self)
        let sourceLength = sourceData.length
        let blockLength =  SecKeyGetBlockSize(priKey)
        var outBuffer = [UInt8](repeating: 0, count: blockLength)
        var outBufferLength:Int = blockLength
        let status = SecKeyRawSign(priKey, padding, sourceBuffer, sourceLength, &outBuffer, &outBufferLength)
        assert(status == errSecSuccess, "Error For SecKeyRawSign: \(status)")
        
        return Data.init(bytes: outBuffer, count: outBufferLength)
    }
    
    /// 验签
    /// - Parameters:
    ///   - source: 签名前的原始数据
    ///   - signData: 已签名的数据，待验签的数据
    public func verify(source: Data, signData: Data) -> Bool {
        guard source.count > 0, signData.count > 0, let pubKey = self.publicSecKey, let _ = self.privateSecKey else { return false }
        guard let sourceData: NSData = source as NSData? else { return false }
        guard let `signData`: NSData = signData as NSData? else { return false }

        let sourceBuffer = sourceData.bytes.assumingMemoryBound(to: UInt8.self) // UnsafePointer<UInt8>
        let sourceLength = sourceData.length
        let signBuffer = signData.bytes.assumingMemoryBound(to: UInt8.self) // UnsafePointer<UInt8>
        let blockLength =  SecKeyGetBlockSize(pubKey)
        
        let status = SecKeyRawVerify(pubKey, padding, sourceBuffer, sourceLength, signBuffer, blockLength)
        assert(status == errSecSuccess, "Error For SecKeyRawVerify: \(status)")
        
        if status == errSecSuccess {
            return true
        }
        return false
    }
}
