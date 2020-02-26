//
//  ViewController.swift
//  SJSecurity
//
//  Created by 周社军 on 2020/2/15.
//  Copyright © 2020 周社军. All rights reserved.
//

import UIKit

class ViewController: UIViewController {

    override func viewDidLoad() {
        super.viewDidLoad()
        // Do any additional setup after loading the view.
    }
    
    override func viewDidAppear(_ animated: Bool) {
        super.viewDidAppear(animated)
        
//        demo1()
//        demo2()
//        demo3()
//        demo4()
//        demo5()
//        demo6()
//        demo7()
//        demo8()
        demo9()
    }
    
    /// CBC 加解密
    func demo1() {
        let message = "999"
//        guard let key = "0123456789123456".data(using: .utf8) else { return } // 16位
//        guard let key = "012345678901234567891234".data(using: .utf8) else { return } // 24 位
        guard let key = "01234567890123456789012345678912".data(using: .utf8) else { return } // 32 位
        
//        guard let iv = "0123456789123456".data(using: .utf8) else { return } // 16位
//        guard let iv = "012345678901234567891234".data(using: .utf8) else { return } // 24 位
        guard let iv = "01234567890123456789012345678912".data(using: .utf8) else { return } // 32 位
        
        let encryptData = message.data(using: .utf8)?.aesCBCEncrypt(key: key, iv: iv)
        if encryptData != nil {
            print("demo1 加密成功，加密前的数据：\(message)")
        }
        else {
            print("demo1 加密失败")
            return
        }
        
        let decryptData = encryptData?.aesCBCDecrypt(key: key, iv: iv)
        if decryptData != nil, let decryptString = String.init(data: decryptData!, encoding: .utf8) {
            print("demo1 解密成功，解密出的数据：\(decryptString)")
        } else {
            print("demo1 解密失败")
        }
    }
    
    /// ECB 加解密
    func demo2() {
        let message = "999"
        guard let key = "0123456789123456".data(using: .utf8) else { return } // 16位
//        guard let key = "012345678901234567891234".data(using: .utf8) else { return } // 24 位
//        guard let key = "01234567890123456789012345678912".data(using: .utf8) else { return } // 32 位
        
        let encryptData = message.data(using: .utf8)?.aesECBEncrypt(key: key)
        if encryptData != nil {
            print("demo2 加密成功，加密前的数据：\(message)")
        }
        else {
            print("demo2 加密失败")
            return
        }
        
        let decryptData = encryptData?.aesECBDecrypt(key: key)
        if decryptData != nil, let decryptString = String.init(data: decryptData!, encoding: .utf8) {
            print("demo2 解密成功，解密出的数据：\(decryptString)")
        } else {
            print("demo2 解密失败")
        }
    }
    
    /// RSA 加解密
    func demo3() {
        var src = ""
        for _ in 0 ..< 117 {
            src += "1"
        }
        print("source length: \(src.count)")
//        初始化方法一：
//        guard let rsaKeyPair = RSAKeyPair.generate() else {
//            print("生成 RSA 密钥对失败")
//            return
//        }
        
//        初始化方法二：
//        let rsaKeyPair = RSAKeyPair()
//        rsaKeyPair.generate()
        
//        初始化方法三：
        let rsaKeyPair = RSAKeyPair.init(algorithm: .rsaEncryptionOAEPSHA256AESGCM)
        rsaKeyPair.generate()
        
        guard let encryptedData = rsaKeyPair.encrypt(source: src.data(using: .utf8)!) else {
            print("RSA 加密失败")
            return
        }
        print("RSA 加密成功。加密前原始数据：\(src)")
        
        guard let decryptedData = rsaKeyPair.decrypt(source: encryptedData) else {
            print("RSA 解密失败")
            return
        }
        guard let decryptedString = String.init(data: decryptedData, encoding: .utf8) else { return }
        print("RSA 解密成功。解密出来的数据：\(decryptedString)")
    }
    
    /// RSA签名与验签
    func demo4() {
        var src = ""
        let length = 128 - 30
        for _ in 0 ..< length {
            src += "1"
        }
        let rsaKeyPair = RSAKeyPair.init(padding: .PKCS1SHA512)
        rsaKeyPair.generate()
        
        let signData = rsaKeyPair.sign(source: src.data(using: .utf8)!)

        if signData != nil {
            print("签名成功：\(signData!.base64EncodedString())")
        }
        else {
            print("签名失败")
            return
        }
        
        let signData2 = rsaKeyPair.sign(source: src.data(using: .utf8)!)

        if signData2 != nil {
            print("签名成功：\(signData2!.base64EncodedString())")
        }
        else {
            print("签名失败")
            return
        }
        
        let status = rsaKeyPair.verify(source: src.data(using: .utf8)!, signData: signData!)
        if status == true {
            print("验签成功")
        }
        else {
            print("验签失败")
        }
    }
    
    /// 读取本地证书公私钥
    func demo5() {
        let pubResource = "public_key.der"
        let priResource = "private_key.p12"
        let password = "123456"
        
        guard let pubFilePath = Bundle.main.path(forResource: pubResource, ofType: nil),
            let priFilePath = Bundle.main.path(forResource: priResource, ofType: nil) else {
                return
        }
        let rsaKeyPair = RSAKeyPair.init(algorithm: .rsaEncryptionPKCS1)
        rsaKeyPair.readPublicSecKey(derFilePath: pubFilePath)
        rsaKeyPair.readP12SecKeys(p12FilePath: priFilePath, password: password)
        
        print("pubKey:\(rsaKeyPair.publicSecKey!)")
        print("priKey:\(rsaKeyPair.privateSecKey!)")
        
        var src = ""
        for _ in 0 ..< 117 {
            src += "1"
        }
        print("source length: \(src.count)")
        guard let encryptedData = rsaKeyPair.encrypt(source: src.data(using: .utf8)!) else {
            print("RSA 加密失败")
            return
        }
        print("RSA 加密成功。加密前原始数据：\(src)")
        
        guard let decryptedData = rsaKeyPair.decrypt(source: encryptedData) else {
            print("RSA 解密失败")
            return
        }
        guard let decryptedString = String.init(data: decryptedData, encoding: .utf8) else { return }
        print("RSA 解密成功。解密出来的数据：\(decryptedString)")
    }
    
    /// 读取本地证书公私钥
    func demo6() {
        let pubResource = "public_key.pem"
        let priResource = "private_key.pem"
        
        guard let pubFilePath = Bundle.main.path(forResource: pubResource, ofType: nil),
            let priFilePath = Bundle.main.path(forResource: priResource, ofType: nil) else {
                return
        }
        let rsaKeyPair = RSAKeyPair.init(algorithm: .rsaEncryptionPKCS1)
        rsaKeyPair.readPublicSecKey(pemFilePath: pubFilePath)
        rsaKeyPair.readPrivateSecKey(pemFilePath: priFilePath)
        print("pubKey:\(rsaKeyPair.publicSecKey!)")
        print("priKey:\(rsaKeyPair.privateSecKey!)")
        
        var src = ""
        for _ in 0 ..< 117 {
            src += "1"
        }
        print("source length: \(src.count)")
        guard let encryptedData = rsaKeyPair.encrypt(source: src.data(using: .utf8)!) else {
            print("RSA 加密失败")
            return
        }
        print("RSA 加密成功。加密前原始数据：\(src)")
        
        guard let decryptedData = rsaKeyPair.decrypt(source: encryptedData) else {
            print("RSA 解密失败")
            return
        }
        guard let decryptedString = String.init(data: decryptedData, encoding: .utf8) else { return }
        print("RSA 解密成功。解密出来的数据：\(decryptedString)")
    }
    
    /// 读取本地证书公私钥
    func demo7() {
        let pubResource = "public_key.pem"
        let priResource = "private_key.p12"
        let password = "123456"
        
        guard let pubFilePath = Bundle.main.path(forResource: pubResource, ofType: nil),
            let priFilePath = Bundle.main.path(forResource: priResource, ofType: nil) else {
                return
        }
        let rsaKeyPair = RSAKeyPair.init(algorithm: .rsaEncryptionPKCS1)
        rsaKeyPair.readPublicSecKey(pemFilePath: pubFilePath)
        rsaKeyPair.readP12SecKeys(p12FilePath: priFilePath, password: password)
        print("pubKey:\(rsaKeyPair.publicSecKey!)")
        print("priKey:\(rsaKeyPair.privateSecKey!)")
        
        var src = ""
        for _ in 0 ..< 117 {
            src += "1"
        }
        print("source length: \(src.count)")
        guard let encryptedData = rsaKeyPair.encrypt(source: src.data(using: .utf8)!) else {
            print("RSA 加密失败")
            return
        }
        print("RSA 加密成功。加密前原始数据：\(src)")
        
        guard let decryptedData = rsaKeyPair.decrypt(source: encryptedData) else {
            print("RSA 解密失败")
            return
        }
        guard let decryptedString = String.init(data: decryptedData, encoding: .utf8) else { return }
        print("RSA 解密成功。解密出来的数据：\(decryptedString)")
    }
    
    /// 读取本地证书公私钥
    func demo8() {
        let priResource = "private_key.p12"
        let password = "123456"
        
        guard let priFilePath = Bundle.main.path(forResource: priResource, ofType: nil) else {
            return
        }
        let rsaKeyPair = RSAKeyPair.init(algorithm: .rsaEncryptionPKCS1)
        rsaKeyPair.readP12SecKeys(p12FilePath: priFilePath, password: password)
        print("pubKey:\(rsaKeyPair.publicSecKey!)")
        print("priKey:\(rsaKeyPair.privateSecKey!)")
        
        var src = ""
        for _ in 0 ..< 117 {
            src += "1"
        }
        print("source length: \(src.count)")
        guard let encryptedData = rsaKeyPair.encrypt(source: src.data(using: .utf8)!) else {
            print("RSA 加密失败")
            return
        }
        print("RSA 加密成功。加密前原始数据：\(src)")
        
        guard let decryptedData = rsaKeyPair.decrypt(source: encryptedData) else {
            print("RSA 解密失败")
            return
        }
        guard let decryptedString = String.init(data: decryptedData, encoding: .utf8) else { return }
        print("RSA 解密成功。解密出来的数据：\(decryptedString)")
    }
    
    /// MD5
    func demo9() {
        let string = "123456"
        let hashValue = string.md5()
        print("md5 hash value:\(hashValue)")
    }
}

