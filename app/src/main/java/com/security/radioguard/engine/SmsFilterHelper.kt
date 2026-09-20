package com.security.radioguard.engine

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.os.Bundle
import android.telephony.SmsMessage
import android.util.Log

object SmsFilterHelper {

    private const val TAG = "SmsFilterHelper"

    data class SmsSecurityResult(
        val isSilentSms: Boolean,
        val isSuspiciousBlaster: Boolean,
        val sender: String,
        val details: String
    )

    fun inspectSmsPdus(pdus: Array<*>, format: String?): List<SmsSecurityResult> {
        val results = mutableListOf<SmsSecurityResult>()

        for (pdu in pdus) {
            val bytes = pdu as? ByteArray ?: continue
            val message = if (format != null) {
                SmsMessage.createFromPdu(bytes, format)
            } else {
                @Suppress("DEPRECATION")
                SmsMessage.createFromPdu(bytes)
            } ?: continue

            val protocolId = message.protocolIdentifier
            val sender = message.originatingAddress ?: "Unknown"

            // 0x40 is TP-PID Short Message Type 0 (Silent Ping)
            val isSilentPing = protocolId == 0x40 || message.isTypeZero

            // Check if sender looks like a spoofed alphanumeric brand tag (e.g., "BankAlert")
            val isAlphaSender = sender.matches(Regex("^[a-zA-Z]{3,11}$"))

            if (isSilentPing) {
                Log.w(TAG, "SURVEILLANCE DETECTED: Silent SMS (Type 0) received from $sender!")
                results.add(
                    SmsSecurityResult(
                        isSilentSms = true,
                        isSuspiciousBlaster = false,
                        sender = sender,
                        details = "Type-0 Silent Ping received (Surveillance vector)"
                    )
                )
            } else if (isAlphaSender) {
                results.add(
                    SmsSecurityResult(
                        isSilentSms = false,
                        isSuspiciousBlaster = true,
                        sender = sender,
                        details = "Alphanumeric shortcode message (potential SMS Blaster injection)"
                    )
                )
            }
        }

        return results
    }
}

class SmsInspectionReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action == "android.provider.Telephony.SMS_RECEIVED") {
            val bundle: Bundle? = intent.extras
            val pdus = bundle?.get("pdus") as? Array<*> ?: return
            val format = bundle.getString("format")

            val findings = SmsFilterHelper.inspectSmsPdus(pdus, format)
            for (finding in findings) {
                if (finding.isSilentSms) {
                    // Alert system or abort broadcast if configured
                    Log.w("SmsInspectionReceiver", "Flagged SMS anomaly: ${finding.details}")
                }
            }
        }
    }
}
