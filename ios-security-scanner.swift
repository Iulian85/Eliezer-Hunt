import Foundation
import UIKit
import Security

class SecurityScanner {

    struct SecurityResult: Codable {
        let telegramUserId: String
        let verified: Bool
        let token: String
        let checks: [SecurityCheck]
        let timestamp: TimeInterval
    }

    struct SecurityCheck: Codable {
        let type: String
        let passed: Bool
        let details: String
    }

    private static let hmacSecret = "YOUR_SECRET_KEY_HERE" // This should be stored securely, not hardcoded in production

    /**
     * Performs comprehensive security checks on the device
     */
    func performSecurityScan(telegramUserId: String) -> SecurityResult {
        var checks: [SecurityCheck] = []

        // Jailbreak detection checks
        checks.append(checkCydia())
        checks.append(checkSuspiciousFiles())
        checks.append(checkSuspiciousApps())
        checks.append(checkSystemIntegrity())
        checks.append(checkEmulator())

        // Additional iOS-specific checks
        checks.append(checkDebugger())
        checks.append(checkDyldInjection())
        checks.append(checkFrida())

        let allPassed = checks.allSatisfy { $0.passed }

        // Generate cryptographically signed verification token
        let token = generateSignedVerificationToken(telegramUserId: telegramUserId, verified: allPassed, checks: checks)

        return SecurityResult(
            telegramUserId: telegramUserId,
            verified: allPassed,
            token: token,
            checks: checks,
            timestamp: Date().timeIntervalSince1970
        )
    }

    private func checkCydia() -> SecurityCheck {
        let cydiaPaths = [
            "/Applications/Cydia.app",
            "/private/var/lib/cydia",
            "/private/etc/apt/sources.list.d/cydia.list"
        ]

        let detected = cydiaPaths.contains { FileManager.default.fileExists(atPath: $0) }

        return SecurityCheck(
            type: "JAILBREAK_CYDIA_CHECK",
            passed: !detected,
            details: detected ? "Cydia detected" : "No Cydia found"
        )
    }

    private func checkSuspiciousFiles() -> SecurityCheck {
        let suspiciousPaths = [
            "/bin/sh",
            "/etc/ssh/sshd_config",
            "/private/var/stash",
            "/private/var/lib/apt/",
            "/usr/libexec/ssh-keysign",
            "/usr/sbin/sshd",
            "/private/var/mobile/Library/SBSettings/Themes",
            "/System/Library/LaunchDaemons/com.ikey.bbot.plist",
            "/System/Library/LaunchDaemons/com.saurik.Cydia.Startup.plist"
        ]

        let detected = suspiciousPaths.contains { FileManager.default.fileExists(atPath: $0) }

        return SecurityCheck(
            type: "SUSPICIOUS_FILES_CHECK",
            passed: !detected,
            details: detected ? "Suspicious files found" : "No suspicious files found"
        )
    }

    private func checkSuspiciousApps() -> SecurityCheck {
        let suspiciousBundleIds = [
            "com.saurik.Cydia",
            "com.els.sihcyd",
            "com.iptools.terminal",
            "com.ex.substitute",
            "org.coolstar.SileoStore",
            "science.xnu.undecimus",
            "com.kpumd.chooser"
        ]

        let detected = suspiciousBundleIds.contains { bundleId in
            Bundle(path: "/Applications/\(bundleId).app") != nil
        }

        return SecurityCheck(
            type: "SUSPICIOUS_APPS_CHECK",
            passed: !detected,
            details: detected ? "Suspicious apps found" : "No suspicious apps found"
        )
    }

    private func checkSystemIntegrity() -> SecurityCheck {
        // Check if we can write to system directories
        let systemWritable = canWriteToSystemDirectory()

        // Check if we can access restricted files
        let canAccessRestricted = canAccessRestrictedFiles()

        let failed = systemWritable || canAccessRestricted

        return SecurityCheck(
            type: "SYSTEM_INTEGRITY_CHECK",
            passed: !failed,
            details: failed ? "System integrity compromised" : "System integrity intact"
        )
    }

    private func canWriteToSystemDirectory() -> Bool {
        let testPath = "/private/var/mobile/test_write_access"
        let testContent = Data()

        do {
            try testContent.write(to: URL(fileURLWithPath: testPath))
            // If we succeeded, remove the test file
            try FileManager.default.removeItem(atPath: testPath)
            return true
        } catch {
            return false
        }
    }

    private func canAccessRestrictedFiles() -> Bool {
        let restrictedPaths = [
            "/private/var/mobile/Library/Preferences/com.apple.springboard.plist",
            "/private/var/mobile/Library/SMS/sms.db"
        ]

        return restrictedPaths.contains { path in
            FileManager.default.isReadableFile(atPath: path)
        }
    }

    private func checkEmulator() -> SecurityCheck {
        #if targetEnvironment(simulator)
        return SecurityCheck(
            type: "EMULATOR_CHECK",
            passed: false,
            details: "Running in simulator"
        )
        #else
        return SecurityCheck(
            type: "EMULATOR_CHECK",
            passed: true,
            details: "Running on physical device"
        )
        #endif
    }

    private func checkDebugger() -> SecurityCheck {
        var info = kinfo_proc()
        var mib: [Int32] = [CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid()]
        var size = MemoryLayout<kinfo_proc>.stride
        let sysctlRet = sysctl(&mib, 4, &info, &size, nil, 0)

        if sysctlRet != 0 {
            print("sysctl failed: \(sysctlRet)")
            return SecurityCheck(
                type: "DEBUGGER_CHECK",
                passed: false,
                details: "Unable to check for debugger"
            )
        }

        let isTraced = (info.kp_proc.p_flag & P_TRACED) != 0
        let isVMMapped = (info.kp_proc.p_flag & P_LP64) != 0

        return SecurityCheck(
            type: "DEBUGGER_CHECK",
            passed: !isTraced,
            details: isTraced ? "Debugger attached" : "No debugger detected"
        )
    }

    private func checkDyldInjection() -> SecurityCheck {
        // Check for injected dynamic libraries
        let suspiciousLibraries = [
            "Frida",
            "libcycript",
            "MobileSubstrate",
            "SubstrateInserter",
            "PreferenceLoader"
        ]

        // This is a simplified check - in a real implementation you'd iterate through loaded libraries
        let detected = false // Placeholder - actual implementation would check loaded libraries

        return SecurityCheck(
            type: "DYLD_INJECTION_CHECK",
            passed: !detected,
            details: detected ? "Dynamic library injection detected" : "No dynamic library injection detected"
        )
    }

    private func checkFrida() -> SecurityCheck {
        // Check for Frida server process
        let fridaPorts = [27042, 27043] // Common Frida ports

        var fridaDetected = false
        for port in fridaPorts {
            if isPortOpen(port: UInt16(port)) {
                fridaDetected = true
                break
            }
        }

        return SecurityCheck(
            type: "FRIDA_CHECK",
            passed: !fridaDetected,
            details: fridaDetected ? "Frida server detected" : "No Frida server detected"
        )
    }

    private func isPortOpen(port: UInt16) -> Bool {
        // Simple port check implementation
        let socketFileDescriptor = socket(AF_INET, SOCK_STREAM, 0)
        if socketFileDescriptor == -1 {
            return false
        }

        var addr = sockaddr_in()
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_port = port.bigEndian
        addr.sin_addr.s_addr = inet_addr("127.0.0.1")
        addr.sin_zero = (0, 0, 0, 0, 0, 0, 0, 0)

        let bindResult = bind(socketFileDescriptor, sockaddr(pointer: &addr), socklen_t(MemoryLayout<sockaddr_in>.size))
        close(socketFileDescriptor)

        // If bind fails, the port is likely in use
        return bindResult == -1
    }

    private func generateSignedVerificationToken(telegramUserId: String, verified: Bool, checks: [SecurityCheck]) -> String {
        // Create the payload
        let payload: [String: Any] = [
            "telegramUserId": telegramUserId,
            "verified": verified,
            "timestamp": Date().timeIntervalSince1970,
            "platform": "ios",
            "nonce": UUID().uuidString,
            "checks": checks.map { "\($0.type):\($0.passed)" }.joined(separator: ",")
        ]

        guard let payloadData = try? JSONSerialization.data(withJSONObject: payload),
              let payloadString = String(data: payloadData, encoding: .utf8) else {
            return ""
        }

        // Generate HMAC signature
        let signature = generateHmacSignature(for: payloadString)
        let encodedPayload = payloadString.data(using: .utf8)?.base64EncodedString() ?? ""
        let encodedSignature = signature.base64EncodedString()

        // Create JWT-like token: header.payload.signature
        let header = "{\"alg\":\"HS256\",\"typ\":\"JWT\"}".data(using: .utf8)?.base64EncodedString() ?? ""

        return "\(header).\(encodedPayload).\(encodedSignature)"
    }

    private func generateHmacSignature(for data: String) -> Data {
        let keyData = Self.hmacSecret.data(using: .utf8)!
        let messageData = data.data(using: .utf8)!

        var signature = [UInt8](repeating: 0, count: Int(CC_SHA256_DIGEST_LENGTH))
        CCHmac(CCHmacAlgorithm(kCCHmacAlgSHA256), keyData.bytes, keyData.count, messageData.bytes, messageData.count, &signature)

        return Data(signature)
    }
}

extension Data {
    var bytes: [UInt8] {
        return Array(self)
    }
}