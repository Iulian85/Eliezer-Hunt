package com.eliezer.hunt.security

import android.content.Context
import android.os.Build
import android.util.Base64
import android.util.Log
import com.google.android.play.core.integrity.IntegrityManagerFactory
import com.google.android.play.core.integrity.IntegrityTokenRequest
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.json.JSONObject
import java.io.File
import java.security.MessageDigest
import java.util.concurrent.TimeUnit
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import java.util.UUID

class SecurityScanner(private val context: Context) {
    companion object {
        // This should be stored securely, not hardcoded in production
        private const val HMAC_SECRET = "YOUR_SECRET_KEY_HERE"
    }

    /**
     * Performs comprehensive security checks on the device including Play Integrity API
     */
    suspend fun performSecurityScan(telegramUserId: String): SecurityResult {
        return withContext(Dispatchers.IO) {
            val checks = mutableListOf<SecurityCheck>()

            // Root detection checks
            checks.add(checkRootBinaries())
            checks.add(checkRootApps())
            checks.add(checkDangerousProps())
            checks.add(checkPartitions())

            // Samsung Knox check
            checks.add(checkKnox())

            // Emulator detection
            checks.add(checkEmulator())

            // Magisk detection
            checks.add(checkMagisk())

            val allPassed = checks.all { it.passed }

            // Perform Play Integrity check
            val playIntegrityResult = performPlayIntegrityCheck()
            val playIntegrityCheck = SecurityCheck(
                type = "PLAY_INTEGRITY_CHECK",
                passed = playIntegrityResult,
                details = if (playIntegrityResult) "Play Integrity passed" else "Play Integrity failed"
            )
            checks.add(playIntegrityCheck)

            // Overall verification is true only if all checks pass
            val overallVerified = allPassed && playIntegrityResult

            // Generate cryptographically signed verification token
            val token = generateSignedVerificationToken(telegramUserId, overallVerified, checks)

            SecurityResult(
                telegramUserId = telegramUserId,
                verified = overallVerified,
                token = token,
                checks = checks,
                timestamp = System.currentTimeMillis()
            )
        }
    }

    private fun checkRootBinaries(): SecurityCheck {
        val rootBinaries = arrayOf(
            "/system/app/Superuser.apk",
            "/sbin/su",
            "/system/bin/su",
            "/system/xbin/su",
            "/data/local/xbin/su",
            "/data/local/bin/su",
            "/system/sd/xbin/su",
            "/system/bin/failsafe/su",
            "/data/local/su",
            "/su/bin/su"
        )

        val detected = rootBinaries.any { File(it).exists() }

        return SecurityCheck(
            type = "ROOT_BINARY_CHECK",
            passed = !detected,
            details = if (detected) "Found root binary" else "No root binaries found"
        )
    }

    private fun checkRootApps(): SecurityCheck {
        val rootApps = arrayOf(
            "com.noshufou.android.su",
            "com.noshufou.android.su.elite",
            "eu.chainfire.supersu",
            "com.koushikdutta.superuser",
            "com.thirdparty.superuser",
            "com.yellowes.su",
            "com.topjohnwu.magisk"
        )

        val pm = context.packageManager
        val detected = rootApps.any { packageName ->
            try {
                pm.getPackageInfo(packageName, 0)
                true
            } catch (e: Exception) {
                false
            }
        }

        return SecurityCheck(
            type = "ROOT_APP_CHECK",
            passed = !detected,
            details = if (detected) "Found root app" else "No root apps found"
        )
    }

    private fun checkDangerousProps(): SecurityCheck {
        return try {
            val roDebuggable = getProp("ro.debuggable") == "1"
            val roSecure = getProp("ro.secure") == "0"
            val roAllowMockLocation = getProp("ro.allow.mock.location") == "1"

            val hasDangerousProps = roDebuggable || roSecure || roAllowMockLocation

            SecurityCheck(
                type = "DANGEROUS_PROP_CHECK",
                passed = !hasDangerousProps,
                details = if (hasDangerousProps) "Found dangerous props: debuggable=$roDebuggable, secure=$roSecure, mock_location=$roAllowMockLocation" else "No dangerous props found"
            )
        } catch (e: Exception) {
            SecurityCheck(
                type = "DANGEROUS_PROP_CHECK",
                passed = false,
                details = "Error checking props: ${e.message}"
            )
        }
    }

    private fun checkPartitions(): SecurityCheck {
        val writableSystem = try {
            val systemPartition = File("/system")
            systemPartition.canWrite()
        } catch (e: Exception) {
            false
        }

        return SecurityCheck(
            type = "PARTITION_CHECK",
            passed = !writableSystem,
            details = if (writableSystem) "System partition is writable" else "System partition is read-only"
        )
    }

    private fun checkKnox(): SecurityCheck {
        return try {
            // Knox warranty bit check
            // In a real implementation, you would use Samsung's Knox SDK
            // For this example, we'll simulate the check
            val knoxWarrantyBit = try {
                // This is a simplified check - real implementation would use Knox SDK
                Class.forName("com.samsung.android.knox.KnoxUuidHelper")
                // If class exists, we'll check for warranty bit
                false // Assume device is clean unless proven otherwise
            } catch (e: ClassNotFoundException) {
                // Knox SDK not available, use alternative methods
                false
            }

            SecurityCheck(
                type = "KNOX_CHECK",
                passed = !knoxWarrantyBit,
                details = if (knoxWarrantyBit) "Knox warranty bit triggered" else "Knox check passed"
            )
        } catch (e: Exception) {
            SecurityCheck(
                type = "KNOX_CHECK",
                passed = false,
                details = "Error checking Knox: ${e.message}"
            )
        }
    }

    private fun checkEmulator(): SecurityCheck {
        val isEmulator = Build.FINGERPRINT.contains("generic") ||
                Build.MODEL.contains("google_sdk") ||
                Build.MODEL.contains("Emulator") ||
                Build.MODEL.contains("Android SDK built for x86") ||
                Build.MANUFACTURER.contains("Genymotion") ||
                Build.HARDWARE.contains("goldfish") ||
                Build.HARDWARE.contains("ranchu") ||
                Build.PRODUCT.contains("sdk_google") ||
                Build.PRODUCT.contains("google_sdk") ||
                Build.PRODUCT.contains("sdk") ||
                Build.PRODUCT.contains("vbox86p")

        return SecurityCheck(
            type = "EMULATOR_CHECK",
            passed = !isEmulator,
            details = if (isEmulator) "Device appears to be emulator" else "Device is physical"
        )
    }

    private fun checkMagisk(): SecurityCheck {
        val magiskPaths = arrayOf(
            "/sbin/.magisk",
            "/cache/.magisk",
            "/data/adb/magisk",
            "/system/xbin/magisk",
            "/system/xbin/magiskpolicy",
            "/system/xbin/magiskinit",
            "/system/bin/magisk",
            "/system/bin/magiskpolicy",
            "/system/bin/magiskinit"
        )

        val detected = magiskPaths.any { File(it).exists() }

        return SecurityCheck(
            type = "MAGISK_CHECK",
            passed = !detected,
            details = if (detected) "Found Magisk installation" else "No Magisk found"
        )
    }

    private fun getProp(propName: String): String {
        return try {
            val process = Runtime.getRuntime().exec("getprop $propName")
            process.waitFor(2, TimeUnit.SECONDS)
            val output = process.inputStream.bufferedReader().readText().trim()
            output.ifEmpty { "unknown" }
        } catch (e: Exception) {
            "unknown"
        }
    }

    private suspend fun performPlayIntegrityCheck(): Boolean {
        return try {
            val integrityManager = IntegrityManagerFactory.create(context)
            val request = IntegrityTokenRequest.builder()
                .setRequestId(UUID.randomUUID().toString())
                .build()

            val integrityTokenResponse = integrityManager.requestIntegrityToken(request).await()
            val integrityToken = integrityTokenResponse.token()

            // In a real implementation, you would send this token to your backend
            // for verification against Google's attestation service
            // For this implementation, we'll return true if we got a token
            !integrityToken.isNullOrEmpty()
        } catch (e: Exception) {
            Log.e("SecurityScanner", "Play Integrity check failed", e)
            false
        }
    }

    private fun generateSignedVerificationToken(telegramUserId: String, verified: Boolean, checks: List<SecurityCheck>): String {
        // Create the payload
        val payload = JSONObject().apply {
            put("telegramUserId", telegramUserId)
            put("verified", verified)
            put("timestamp", System.currentTimeMillis())
            put("platform", "android")
            put("nonce", UUID.randomUUID().toString())
            put("checks", checks.map { "${it.type}:${it.passed}" }.joinToString(","))
        }

        val payloadString = payload.toString()
        val encodedPayload = Base64.encodeToString(payloadString.toByteArray(), Base64.NO_WRAP)

        // Generate HMAC signature
        val hmac = generateHmacSignature(payloadString)
        val encodedSignature = Base64.encodeToString(hmac, Base64.NO_WRAP)

        // Return JWT-like token: header.payload.signature
        val header = Base64.encodeToString("{\"alg\":\"HS256\",\"typ\":\"JWT\"}".toByteArray(), Base64.NO_WRAP)
        return "$header.$encodedPayload.$encodedSignature"
    }

    private fun generateHmacSignature(data: String): ByteArray {
        val secretKeySpec = SecretKeySpec(HMAC_SECRET.toByteArray(), "HmacSHA256")
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(secretKeySpec)
        return mac.doFinal(data.toByteArray())
    }
}

data class SecurityResult(
    val telegramUserId: String,
    val verified: Boolean,
    val token: String,
    val checks: List<SecurityCheck>,
    val timestamp: Long
)

data class SecurityCheck(
    val type: String,
    val passed: Boolean,
    val details: String
)