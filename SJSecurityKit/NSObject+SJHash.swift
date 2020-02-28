//
//  NSObject+SJHash.swift
//  SJSecurity
//
//  Created by 周社军 on 2020/2/26.
//  Copyright © 2020 周社军. All rights reserved.
//

import Foundation
import CommonCrypto

extension String {
    @available(iOS, deprecated: 13.0, message: "This function is cryptographically broken and should not be used in security contexts. Clients should migrate to SHA256 (or stronger).")
    public func md5() -> String {
        let context = UnsafeMutablePointer<CC_MD5_CTX>.allocate(capacity: 1)
        var digest = Array<UInt8>(repeating:0, count:Int(CC_MD5_DIGEST_LENGTH))
        CC_MD5_Init(context)
        CC_MD5_Update(context, self, CC_LONG(self.lengthOfBytes(using: String.Encoding.utf8)))
        CC_MD5_Final(&digest, context)
        context.deallocate()
        var hexString = ""
        for byte in digest {
            hexString += String(format:"%02x", byte)
        }
        
        return hexString
    }
}
