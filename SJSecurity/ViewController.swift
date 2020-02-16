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
//        demo1()
//        demo2()
        demo3()
    }

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
    
    func demo3() {
        let src = "abcdefg"
//        guard let rsaKeyPair = RSAKeyPair.generate() else {
//            print("生成 RSA 密钥对失败")
//            return
//        }
        
//        let rsaKeyPair = RSAKeyPair()
//        rsaKeyPair.generate()
        
        let rsaKeyPair = RSAKeyPair.init()
        rsaKeyPair.generate()
        
        guard let encryptResult = rsaKeyPair.encrypt(source: src) else {
            print("RSA 加密失败")
            return
        }
        print("RSA 加密成功。加密前原始数据：\(src)")
        
        guard let decryptResult = rsaKeyPair.decrypt(source: encryptResult) else {
            print("RSA 解密失败")
            return
        }
        print("RSA 解密成功。解密出来的数据：\(decryptResult)")
    }
}

